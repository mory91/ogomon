package internal

import (
	"github.com/prometheus/procfs"
	"time"
)

type DataTicker func(t time.Time, tracer *SystemTracer)

type SystemTracer struct {
	proc         *procfs.Proc
	traceChannel chan Trace
	prevVal      uint64
	ticker       DataTicker
}

func NewDiskReadTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickDiskRead}, nil
}

func NewDiskWriteTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickDiskWrite}, nil
}

func NewMemoryTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickMemory}, nil
}

func tickDiskRead(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	readBytes := stat.ReadBytes - tracer.prevVal
	tracer.prevVal = stat.ReadBytes
	tracer.traceChannel <- Trace{TS: uint64(t.UnixNano()), Data: readBytes}
}

func tickDiskWrite(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	writeBytes := stat.WriteBytes - tracer.prevVal
	tracer.prevVal = stat.WriteBytes
	tracer.traceChannel <- Trace{TS: uint64(t.UnixNano()), Data: writeBytes}
}

func tickMemory(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedVm := uint64(stat.VSize) - tracer.prevVal
	tracer.prevVal = uint64(stat.VSize)
	tracer.traceChannel <- Trace{TS: uint64(t.UnixNano()), Data: allocatedVm}
}

func (systemTracer SystemTracer) Start(ticker time.Ticker, stop chan bool) {
	for {
		select {
		case t := <-ticker.C:
			systemTracer.ticker(t, &systemTracer)
		case <-stop:
			close(systemTracer.traceChannel)
			return
		}
	}
}

func (systemTracer SystemTracer) Chan() chan Trace {
	return systemTracer.traceChannel
}
