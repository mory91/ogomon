package ebpf

import (
	"errors"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	jww "github.com/spf13/jwalterweatherman"
	"ogomon/internal"
	"time"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@master -type event tcACL ../../ebpf/tc_acl.c -- -I../../ebpf/include -nostdinc -O3

type NetworkTracer struct {
	traceChannel chan internal.Trace
	srcPort      int
	destPort     int
	ebpfObjs     *tcACLObjects
}

func NewNetworkTracer(srcPort, destPort int) (NetworkTracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return NetworkTracer{}, err
	}
	var objs tcACLObjects
	if err := loadTcACLObjects(&objs, nil); err != nil {
		return NetworkTracer{}, err
	}
	nt := NetworkTracer{
		traceChannel: make(chan internal.Trace, 10000),
		srcPort:      srcPort,
		destPort:     destPort,
		ebpfObjs:     &objs,
	}
	return nt, nil
}

func (tracer NetworkTracer) Start(ticker time.Ticker, stop chan bool) {
	err := tracer.getEbpfObjects().PortHolder.Put(uint64(0), uint64(tracer.srcPort))
	err = tracer.getEbpfObjects().PortHolder.Put(uint64(1), uint64(tracer.destPort))
	keysOut = make([]uint64, 5000)
	valsOut = make([]tcACLEvent, 5000)
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

func (tracer NetworkTracer) Chan() chan internal.Trace {
	return tracer.traceChannel
}

func (tracer NetworkTracer) tearDown() {
	tracer.ebpfObjs.Close()
}

func (tracer NetworkTracer) getEbpfObjects() *tcACLObjects {
	return tracer.ebpfObjs
}

func (tracer NetworkTracer) tickFrameSize() {
	var nextKeyOut uint64
	prevKey := new(uint64)
	for {
		_, err := tracer.getEbpfObjects().PacketFrameHolder.BatchLookupAndDelete(prevKey, &nextKeyOut, keysOut, valsOut, nil)
		idx := uint64(0)
		for keysOut[idx] != 0 && valsOut[idx].Sport != 0 {
			nt := internal.NetworkTrace{Len: valsOut[idx].Len, Sport: valsOut[idx].Sport, Dport: valsOut[idx].Dport}
			// TODO: There is a bug here, some 0s for time has been seen.
			tracer.traceChannel <- internal.Trace{TS: keysOut[idx], Data: nt}
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
