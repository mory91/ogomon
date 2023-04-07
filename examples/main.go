package main

import (
	"fmt"
	"log"
	"net"
	_ "strconv"
	"syscall"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pfring"
	"github.com/google/gopacket/layers"
)

func readRAWSocket() {
	proto := (syscall.ETH_P_ALL<<8)&0xff00 | syscall.ETH_P_ALL>>8 // change to Big-Endian order
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, proto)
	if err != nil {
		log.Fatal("socket: ", err)
	}
	defer syscall.Close(fd)
	ifi, err := net.InterfaceByName("eno1")
	if err != nil {
		log.Fatal("interfacebyname: ", err)
	}
	lla := syscall.SockaddrLinklayer{Protocol: uint16(proto), Ifindex: ifi.Index}
	if err := syscall.Bind(fd, &lla); err != nil {
		log.Fatal("bind: ", err)
	}

	buf := make([]byte, 65536)
	count := 0

	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			log.Println("Error:", err)
				continue
		}
		if n <= 0 {
			continue
		}
		count += 1
		if count % 10000 == 0 {
			fmt.Println(count)
		}
		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeEthernet, gopacket.NoCopy)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			transport := packet.TransportLayer().TransportFlow()
			n_layer := packet.NetworkLayer()
			network := n_layer.NetworkFlow()
			src_ip := network.Src().String()
			dest_ip := network.Dst().String()
			src_port := transport.Src().String()
			dest_port := transport.Dst().String()
			d := fmt.Sprintf("%s,%s,%s,%s,%d\n", src_ip, dest_ip, src_port, dest_port, n)
			fmt.Print(d)
	}
	}
}

func ReadFromSource() {
	if ring, err := pfring.NewRing("eno1", 56, pfring.FlagPromisc); err != nil {
		panic(err)
	} else if err := ring.SetSocketMode(pfring.ReadOnly); err != nil {
		panic(err)
	} else if err := ring.Enable(); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(ring, layers.LinkTypeEthernet)
		for packet := range packetSource.Packets() {
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				transport := packet.TransportLayer().TransportFlow()
				n_layer := packet.NetworkLayer()
				network := n_layer.NetworkFlow()
				src_ip := network.Src().String()
				dest_ip := network.Dst().String()
				src_port := transport.Src().String()
				dest_port := transport.Dst().String()
				length := packet.Metadata().Length
				d := fmt.Sprintf("%s,%s,%s,%s,%d\n", src_ip, dest_ip, src_port, dest_port, length)
				fmt.Print(d)
			}
		}
	}
}

func main() {
	ReadFromSource()
}
