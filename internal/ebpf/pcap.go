package ebpf

import (
	"bufio"
	"fmt"
	"os"
	"time"
	"io"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pfring"
	jww "github.com/spf13/jwalterweatherman"
)

type PacketCaptureTracer struct {
	ring *pfring.Ring
	writer *bufio.Writer
	traceFile    *os.File
}

func NewPacketCaptureTracer(deviceName string, appendFile bool) (PacketCaptureTracer, error) {
	ring, err := pfring.NewRing(deviceName, 56, pfring.FlagPromisc)
	if err != nil {
		if err != nil {
			return PacketCaptureTracer{}, err
		}
	} else if err := ring.SetSocketMode(pfring.ReadOnly); err != nil {
		if err != nil {
			return PacketCaptureTracer{}, err
		}
	} else if err := ring.Enable(); err != nil {
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
	return PacketCaptureTracer{ring: ring, writer: writer, traceFile: l}, nil
}

func (tracer PacketCaptureTracer) TearDown() {
	tracer.ring.Close()
	tracer.writer.Flush()
	tracer.traceFile.Close()
}

func (tracer PacketCaptureTracer) GetTickerTime() time.Duration {
	return time.Second
}

func (tracer PacketCaptureTracer) Start(stop chan bool) {
	packetSource := gopacket.NewPacketSource(tracer.ring, layers.LinkTypeEthernet)
	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			jww.ERROR.Println("END")
			break
		} else if err != nil {
			jww.ERROR.Println("Error:", err)
			break
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			transport := packet.TransportLayer().TransportFlow()
			network := packet.NetworkLayer().NetworkFlow()
			src_ip := network.Src().String()
			dest_ip := network.Dst().String()
			src_port := transport.Src().String()
			dest_port := transport.Dst().String()
			length := packet.Metadata().Length
			currentTime := packet.Metadata().Timestamp.UnixNano()
			data := fmt.Sprintf(
				"%d,%d,%s,%s,%s,%s\n",
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
