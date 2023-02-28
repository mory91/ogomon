package ebpf

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	jww "github.com/spf13/jwalterweatherman"

	"github.com/rs/zerolog"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@master -type event tcACL ../../ebpf/tc_acl.c -- -I../../ebpf/include -nostdinc -O3

type NetworkTracer struct {
	srcPort      int
	destPort     int
	ebpfObjs     *tcACLObjects
	logger       zerolog.Logger
}

func NewNetworkTracer(srcPort, destPort int) (NetworkTracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return NetworkTracer{}, err
	}
	var objs tcACLObjects
	if err := loadTcACLObjects(&objs, nil); err != nil {
		return NetworkTracer{}, err
	}
	l, _ := os.OpenFile("records/packets", os.O_RDWR|os.O_CREATE, 0777)
	log := zerolog.New(l)
	nt := NetworkTracer{
		srcPort:      srcPort,
		destPort:     destPort,
		ebpfObjs:     &objs,
		logger:	      log,
	}
	return nt, nil
}

func (tracer NetworkTracer) Start(ticker time.Ticker, stop chan bool) {
	err := tracer.getEbpfObjects().PortHolder.Put(uint64(0), uint64(tracer.srcPort))
	err = tracer.getEbpfObjects().PortHolder.Put(uint64(1), uint64(tracer.destPort))
	keysOut = make([]uint64, 100000)
	valsOut = make([]tcACLEvent, 100000)
	if err != nil {
		jww.INFO.Println(err)
	}
	for {
		select {
		case <-ticker.C:
			tracer.tickFrameSize()
		case <-stop:
			tracer.tearDown()
			return
		}
	}
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
		_, err := tracer.getEbpfObjects().Events.BatchLookupAndDelete(prevKey, &nextKeyOut, keysOut, valsOut, nil)
		idx := uint64(0)
		for keysOut[idx] != 0 && valsOut[idx].Sport != 0 {
			// TODO: There is a bug here, some 0s for time has been seen.
			data := fmt.Sprintf(
				"%d,%d,%d,%d,%d,%d", 
				keysOut[idx], 
				valsOut[idx].Len, 
				valsOut[idx].Saddr, 
				valsOut[idx].Daddr, 
				valsOut[idx].Sport, 
				valsOut[idx].Dport, 
			)
			tracer.logger.Log().Str("r", data)
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
