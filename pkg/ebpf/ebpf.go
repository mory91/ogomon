package ebpf

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@master -type packet_frame xdpACL ../../ebpf/xdp_acl.c -- -I../../ebpf/include -nostdinc -O3

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

func ccz() {

	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		fmt.Println("WARNING: Failed to adjust rlimit")
	}

	var objs xdpACLObjects

	if err := loadXdpACLObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	link, err := netlink.LinkByName("wlp2s0")
	if err != nil {
		panic(err)
	}

	info, _ := objs.TcSay.Info()

	fmt.Println("info.Name: ", info.Name)

	filterattrs := netlink.FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Handle:    netlink.MakeHandle(0, 1),
		Protocol:  unix.ETH_P_ALL,
		Priority:  1,
	}
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err := netlink.QdiscAdd(qdisc); err != nil {
		fmt.Println("QdiscAdd err: ", err.Error())
	}

	filter := &netlink.BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           objs.TcSay.FD(),
		Name:         "hi-tc",
		DirectAction: true,
	}

	if err := netlink.FilterAdd(filter); err != nil {
		fmt.Println("FilterAdd err: ", err)
		panic(err)
	}

	defer func() {
		err = netlink.FilterDel(filter)
		if err != nil {
			fmt.Println("FilterDel err : ", err.Error())
		}
		if err := netlink.QdiscDel(qdisc); err != nil {
			fmt.Println("QdiscDel err: ", err.Error())
		}
	}()

	objs.PortHolder.Put(uint64(0), uint64(443))
	go printFrameSize(&objs)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	log.Println("Press CTRL+C to stop.")

	for range signalChan {
		close(signalChan)
		cleanUp(link)
	}

}

func cleanUp(link netlink.Link) {
	fmt.Println("----- cleanUp")
	netlink.LinkSetXdpFdWithFlags(link, -1, xdpFlags((link).Type()))
}

func xdpFlags(linkType string) int {
	if linkType == "veth" || linkType == "tuntap" {
		return 2
	}
	return 0 // native xdp (xdpdrv) by default
}

func printFrameSize(objs *xdpACLObjects) {
	for range time.Tick(time.Millisecond * 10) {
		var packetFrame xdpACLPacketFrame
		if err := objs.PacketFrameHolder.LookupAndDelete(nil, &packetFrame); err == nil {
			fmt.Println(packetFrame.PacketSize, packetFrame.Ktime)
		}
	}
}
