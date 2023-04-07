package ebpf

import (
	"bufio"
	"fmt"
	"ogomon/pkg"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
)

type PacketCaptureTracer struct {
	ring pfring.Ring
	wirter *bufio.Writer
	traceFile    *os.File
}

func NewPacketCaptureTracer(deviceName string, appendFile bool) (PacketCaptureTracer, error) {
	ring, err := pfring.newring(deviceName, 56, pfring.flagpromisc)
	if err != nil {
		if err != nil {
			return PacketCaptureTracer{}, err
		}
	} else if err := ring.setsocketmode(pfring.readonly); err != nil {
		if err != nil {
			return PacketCaptureTracer{}, err
		}
	} else if err := ring.enable(); err != nil {
		if err != nil {
			return PacketCaptureTracer{}, err
		}
	}
	var l *os.File
	if !appendFile {
		l, _ = os.Create("records/packets")
	} else {
		l, _ = os.OpenFile("records/packets", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(l)
	return PacketCaptureTracer{ring: ring, wirter: writer, traceFile: l}, nil
}

func (tracer PacketCaptureTracer) TearDown() {
	tracer.ring.Close()
	tracer.traceFile.Close()
}

func (tracer PacketCaptureTracer) GetTickerTime() time.Duration {
	return time.Second
}

func (tracer PacketCaptureTracer) Start(stop chan bool) {
	packetSource := gopacket.NewPacketSource(tracer.ring, layers.LinkTypeEthernet)
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			transport := packet.TransportLayer().TransportFlow()
			network := packet.NetworkLayer().NetworkFlow()
			src_ip := network.Src().String()
			dest_ip := network.Dst().String()
			src_port := transport.Src().String()
			dest_port := transport.Dst().String()
			length := packet.Metadata().Length
			currentTime := pkg.GetBootTime()
			data := fmt.Sprintf(
				"%d,%s,%s,%s,%s,%d\n",
				currentTime,
				length,
				src_ip, 
				dest_ip,
				src_port,
				dest_port, 
			)
			tracer.writer.WriteString(data)
		}
	}
}
