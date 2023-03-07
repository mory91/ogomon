package ebpf

import (
	"golang.org/x/sys/unix"
	"net"
	"ogomon/pkg"
	"syscall"
)

/*
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

bool set_promisc(char *name, int sock) {
    struct ifreq ethreq;
	strncpy(ethreq.ifr_name, name, IF_NAMESIZE);
	if (ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1) {
		printf("SAG");
    	exit(1);
	}
	ethreq.ifr_flags |= IFF_PROMISC;
	if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1) {
		printf("SAG");
    	exit(1);
	}
}
*/
import "C"

func SetPromiscuous(i net.Interface, fd C.int) (bool, error) {
	set, err := C.set_promisc(C.CString(i.Name), fd)
	return bool(set), err
}

type FilterSocketTracer struct {
	socketFD int
	NetworkTracer
}

func NewFilterSocketTracer(deviceName string, srcPort, destPort int, appendFile bool) (FilterSocketTracer, error) {
	iface := net.Interface{
		Name: deviceName,
	}
	nt, err := NewNetworkTracer(srcPort, destPort, appendFile)
	if err != nil {
		return FilterSocketTracer{}, err
	}
	socket, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(pkg.Htons(syscall.ETH_P_ALL)))
	err = syscall.BindToDevice(socket, iface.Name)
	SetPromiscuous(iface, C.int(socket))
	if err != nil {
		return FilterSocketTracer{}, err
	}
	ssoErr := syscall.SetsockoptInt(socket, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, nt.ebpfObjs.ReportPacketSize.FD())
	if ssoErr != nil {
		return FilterSocketTracer{}, ssoErr
	}
	return FilterSocketTracer{socketFD: socket, NetworkTracer: nt}, nil
}

func (tracer FilterSocketTracer) tearDown() {
	syscall.Close(tracer.socketFD)
	tracer.NetworkTracer.tearDown()
}
