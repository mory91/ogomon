package internal

import (
	"time"

	"github.com/prometheus/procfs"
)

type DataTicker func(t time.Time, tracer *SystemTracer)

type SystemTracer struct {
	proc         *procfs.Proc
	traceChannel chan Trace
	ticker       DataTicker
}

func NewDiskReadTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickDiskRead}, nil
}

func NewDiskWriteTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickDiskWrite}, nil
}

func NewMemoryTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickVirtualMemory}, nil
}

func NewResidentMemoryTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickResidentMemory}, nil
}

func NewDataVirtualMemoryTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickDataVirtualMemory}, nil
}

func NewSTimeTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickSTime}, nil
}

func NewUTimeTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickUTime}, nil
}

func NewCSTimeTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickCSTime}, nil
}

func NewCUTimeTracer(proc *procfs.Proc) (SystemTracer, error) {
	return SystemTracer{proc: proc, traceChannel: make(chan Trace, 5000), ticker: tickCUTime}, nil
}

func tickDiskRead(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	readBytes := stat.ReadBytes
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: readBytes}
}

func tickDiskWrite(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	writeBytes := stat.WriteBytes
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: writeBytes}
}

func tickVirtualMemory(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedVm := uint64(stat.VirtualMemory())
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: allocatedVm}
}

func tickResidentMemory(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedRss := uint64(stat.ResidentMemory())
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: allocatedRss}
}

func tickDataVirtualMemory(t time.Time, tracer *SystemTracer) {
	status, _ := tracer.proc.NewStatus()
	allocatedVmData := uint64(status.VmData)
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: allocatedVmData}
}

func tickCSTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedCSTime := uint64(stat.CSTime)
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: recordedCSTime}
}

func tickCUTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedCUTime := uint64(stat.CUTime)
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: recordedCUTime}
}

func tickSTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedSTime := uint64(stat.STime)
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: recordedSTime}
}

func tickUTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedUTime := uint64(stat.UTime)
	tracer.traceChannel <- Trace{TS: GetEventTime(t), Data: recordedUTime}
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
