package internal

import (
	"time"

	"github.com/prometheus/procfs"
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

func NewResidentMemoryTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickResidentMemory}, nil
}

func tickDiskRead(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	readBytes := stat.ReadBytes - tracer.prevVal
	tracer.prevVal = stat.ReadBytes
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: readBytes}
}

func tickDiskWrite(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	writeBytes := stat.WriteBytes - tracer.prevVal
	tracer.prevVal = stat.WriteBytes
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: writeBytes}
}

func tickMemory(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedVm := uint64(stat.VirtualMemory()) - tracer.prevVal
	tracer.prevVal = uint64(stat.VirtualMemory())
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: allocatedVm}
}

func tickResidentMemory(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedRss := uint64(stat.ResidentMemory()) - tracer.prevVal
	tracer.prevVal = uint64(stat.ResidentMemory())
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: allocatedRss}
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
