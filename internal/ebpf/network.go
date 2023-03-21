package ebpf

import (
	"errors"
	"fmt"
	"os"
	"time"
	"bufio"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	jww "github.com/spf13/jwalterweatherman"
)

const (
	NET_STAT_STEP        = 50
	NET_STAT_TICKER_TIME = time.Microsecond * NET_STAT_STEP
)


//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@master -type event tcACL ../../ebpf/tc_acl.c -- -I../../ebpf/include -nostdinc -O3

type NetworkTracer struct {
	srcPort      int
	destPort     int
	ebpfObjs     *tcACLObjects
	writer       *bufio.Writer
	tickerTime   time.Duration
	traceFile    *os.File
}

func NewNetworkTracer(srcPort, destPort int, appendFile bool) (NetworkTracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return NetworkTracer{}, err
	}
	var objs tcACLObjects
	if err := loadTcACLObjects(&objs, nil); err != nil {
		return NetworkTracer{}, err
	}
	var l *os.File
	if !appendFile {
		l, _ = os.Create("records/packets")
	} else {
		l, _ = os.OpenFile("records/packets", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(l)
	nt := NetworkTracer{
		srcPort:      srcPort,
		destPort:     destPort,
		ebpfObjs:     &objs,
		writer:	      writer,
		tickerTime:   NET_STAT_TICKER_TIME,
		traceFile:    l,
	}
	return nt, nil
}

func (tracer NetworkTracer) Start(ticker time.Ticker, stop chan bool) {
	err := tracer.getEbpfObjects().PortHolder.Put(uint64(0), uint64(tracer.srcPort))
	err = tracer.getEbpfObjects().PortHolder.Put(uint64(1), uint64(tracer.destPort))
	keysOut = make([]uint64, 1000000)
	valsOut = make([]tcACLEvent, 1000000)
	if err != nil {
		jww.INFO.Println(err)
	}
	for {
		select {
		case <-ticker.C:
			tracer.tickFrameSize()
		case <-stop:
			tracer.TearDown()
			return
		}
	}
}

func (tracer NetworkTracer) GetTickerTime() time.Duration {
	return tracer.tickerTime
}


func (tracer NetworkTracer) TearDown() {
	tracer.writer.Flush()
	tracer.ebpfObjs.Close()
	tracer.traceFile.Close()
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
				"%d,%d,%d,%d,%d,%d\n", 
				keysOut[idx], 
				valsOut[idx].Len, 
				valsOut[idx].Saddr, 
				valsOut[idx].Daddr, 
				valsOut[idx].Sport, 
				valsOut[idx].Dport, 
			)
			tracer.writer.WriteString(data)
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
	tracer.writer.Flush()
}
