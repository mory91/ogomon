package ebpf

import (
	"errors"
	"ogomon/internal"
	"ogomon/pkg"
	"time"

	"github.com/cilium/ebpf"
	jww "github.com/spf13/jwalterweatherman"
	"golang.org/x/sys/unix"

	"github.com/vishvananda/netlink"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@master  tcACL ../../ebpf/tc_acl.c -- -I../../ebpf/include -nostdinc -O3

const (
	EGRESS Direction = iota
	INGRESS
)
const (
	XDP_FLAGS_UPDATE_IF_NOEXIST = 1 << 0

	XDP_FLAGS_AUTO_MODE = 0 // custom
	XDP_FLAGS_SKB_MODE  = 1 << 1
	XDP_FLAGS_DRV_MODE  = 1 << 2
	XDP_FLAGS_HW_MODE   = 1 << 3
	XDP_FLAGS_REPLACE   = 1 << 4

	XDP_FLAGS_MODES = XDP_FLAGS_SKB_MODE | XDP_FLAGS_DRV_MODE | XDP_FLAGS_HW_MODE
	XDP_FLAGS_MASK  = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_MODES | XDP_FLAGS_REPLACE
)

var (
	keysOut []uint64
	valsOut []uint64
	qdisc   *netlink.GenericQdisc
)

type TcFilter struct {
	ebpfObjs *tcACLObjects
	tearDown Cleaner
}

type Direction uint32

type TcNetworkTracer struct {
	tcFilter     *TcFilter
	traceChannel chan internal.Trace
	srcPort      int
	destPort     int
	direction    Direction
}

type Cleaner func()

func NewTcNetworkTracer(deviceName string, srcPort, destPort int, direction Direction) (TcNetworkTracer, error) {
	pkg.OpenMemLock()
	var netlinkDir uint32
	if direction == EGRESS {
		netlinkDir = netlink.HANDLE_MIN_EGRESS
	} else if direction == INGRESS {
		netlinkDir = netlink.HANDLE_MIN_INGRESS
	} else {
		return TcNetworkTracer{}, errors.New("undefined direction")
	}
	tcFilter, err := NewTcFilter(deviceName, netlinkDir)
	if err != nil {
		return TcNetworkTracer{}, err
	}
	return TcNetworkTracer{tcFilter: tcFilter, traceChannel: make(chan internal.Trace, 10000), srcPort: srcPort, destPort: destPort}, nil
}

func (tracer TcNetworkTracer) getEbpfObjects() *tcACLObjects {
	return tracer.tcFilter.ebpfObjs
}

func (tracer TcNetworkTracer) Start(ticker time.Ticker, stop chan bool) {
	err := tracer.tcFilter.ebpfObjs.PortHolder.Put(uint64(0), uint64(tracer.srcPort))
	err = tracer.tcFilter.ebpfObjs.PortHolder.Put(uint64(1), uint64(tracer.destPort))
	keysOut = make([]uint64, 5000)
	valsOut = make([]uint64, 5000)
	if err != nil {
		jww.INFO.Println(err)
	}
	for {
		select {
		case <-ticker.C:
			tracer.tickFrameSize()
		case <-stop:
			tracer.tearDown()
			close(tracer.traceChannel)
			return
		}
	}
}

func (tracer TcNetworkTracer) Chan() chan internal.Trace {
	return tracer.traceChannel
}

func (tracer TcNetworkTracer) tearDown() {
	tracer.tcFilter.tearDown()
}

func InitQdisc(link netlink.Link) *netlink.GenericQdisc {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc = &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}
	return qdisc
}

func InitFilter(link netlink.Link, objs tcACLObjects, netlinkDir uint32) *netlink.BpfFilter {
	filterattrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlinkDir,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	var name string
	if netlinkDir == netlink.HANDLE_MIN_EGRESS {
		name = "report-egress"
	} else {
		name = "report-ingress"
	}
	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           objs.ReportPacketSize.FD(),
		Name:         name,
		DirectAction: true,
	}
	return filter
}

func NewTcFilter(deviceName string, netlinkDir uint32) (*TcFilter, error) {
	var objs tcACLObjects
	link, err := netlink.LinkByName(deviceName)
	if err != nil {
		return &TcFilter{}, err
	}

	if err := loadTcACLObjects(&objs, nil); err != nil {
		return &TcFilter{}, err
	}

	if qdisc == nil {
		qdisc = InitQdisc(link)
	}
	filter := InitFilter(link, objs, netlinkDir)
	qdiscList, _ := netlink.QdiscList(link)
	addQdisc := true
	for _, q := range qdiscList {
		if q.Attrs().Parent == netlink.HANDLE_CLSACT {
			addQdisc = false
			break
		}
	}
	if addQdisc {
		if err := netlink.QdiscAdd(qdisc); err != nil {
			jww.ERROR.Println("QdiscAdd err: ", err.Error())
			return &TcFilter{}, err
		}
	}
	if err := netlink.FilterAdd(filter); err != nil {
		jww.ERROR.Println("FilterAdd err: ", err)
		return &TcFilter{}, err
	}

	teardownFilter := func() {
		netlink.FilterDel(filter)
		netlink.QdiscDel(qdisc)
		netlink.LinkSetXdpFdWithFlags(link, -1, xdpFlags((link).Type()))
		objs.Close()
	}

	return &TcFilter{ebpfObjs: &objs, tearDown: teardownFilter}, nil
}

func xdpFlags(linkType string) int {
	if linkType == "veth" || linkType == "tuntap" {
		return 2
	}
	return 0 // native xdp (xdpdrv) by default
}

func (tracer TcNetworkTracer) tickFrameSize() {
	var nextKeyOut uint64
	prevKey := new(uint64)
	for {
		_, err := tracer.getEbpfObjects().PacketFrameHolder.BatchLookupAndDelete(prevKey, &nextKeyOut, keysOut, valsOut, nil)
		idx := uint64(0)
		for keysOut[idx] != 0 {
			tracer.traceChannel <- internal.Trace{TS: keysOut[idx], Data: valsOut[idx]}
			idx++
		}
		if err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				prevKey = nil
				break
			} else {
				jww.ERROR.Println(err)
				break
			}
		} else {
			prevKey = &nextKeyOut
		}
	}
}
