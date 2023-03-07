package ebpf

import (
	"errors"
	jww "github.com/spf13/jwalterweatherman"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	EGRESS Direction = iota
	INGRESS
)

var (
	keysOut []uint64
	valsOut []tcACLEvent
	qdisc   *netlink.GenericQdisc
)

type TcFilter struct {
	tearDown Cleaner
}

type Direction uint32

type TcNetworkTracer struct {
	tcFilter  *TcFilter
	direction Direction
	NetworkTracer
}

type Cleaner func()

func NewTcNetworkTracer(deviceName string, srcPort, destPort int, direction Direction) (TcNetworkTracer, error) {
	nt, err := NewNetworkTracer(srcPort, destPort, false)
	if err != nil {
		return TcNetworkTracer{}, err
	}

	var netlinkDir uint32
	if direction == EGRESS {
		netlinkDir = netlink.HANDLE_MIN_EGRESS
	} else if direction == INGRESS {
		netlinkDir = netlink.HANDLE_MIN_INGRESS
	} else {
		return TcNetworkTracer{}, errors.New("undefined direction")
	}
	tcFilter, err := NewTcFilter(deviceName, netlinkDir, *nt.ebpfObjs)
	if err != nil {
		return TcNetworkTracer{}, err
	}

	return TcNetworkTracer{
		tcFilter:      tcFilter,
		NetworkTracer: nt,
	}, nil
}

func (tracer TcNetworkTracer) tearDown() {
	tracer.NetworkTracer.tearDown()
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

func NewTcFilter(deviceName string, netlinkDir uint32, filterObjs tcACLObjects) (*TcFilter, error) {
	link, err := netlink.LinkByName(deviceName)
	if err != nil {
		return &TcFilter{}, err
	}

	if qdisc == nil {
		qdisc = InitQdisc(link)
	}
	filter := InitFilter(link, filterObjs, netlinkDir)
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
	}

	return &TcFilter{tearDown: teardownFilter}, nil
}

func xdpFlags(linkType string) int {
	if linkType == "veth" || linkType == "tuntap" {
		return 2
	}
	return 0 // native xdp (xdpdrv) by default
}
