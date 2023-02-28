package internal

import (
	"fmt"
	"os"
	"time"

	"github.com/prometheus/procfs"
	"github.com/rs/zerolog"
)

type DataTicker func(t time.Time, tracer *SystemTracer)

type SystemTracer struct {
	proc         *procfs.Proc
	ticker       DataTicker
	logger       zerolog.Logger
}

func NewDiskReadTracer(proc *procfs.Proc) (SystemTracer, error) {
	logFile, _ := os.Create("records/disk_read")
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickDiskRead, logger: logger}, nil
}

func NewDiskWriteTracer(proc *procfs.Proc) (SystemTracer, error) {
	logFile, _ := os.Create("records/disk_write")
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickDiskWrite, logger: logger}, nil
}

func NewMemoryTracer(proc *procfs.Proc) (SystemTracer, error) {
	logFile, _ := os.Create("records/memory")
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickVirtualMemory, logger: logger}, nil
}

func NewResidentMemoryTracer(proc *procfs.Proc) (SystemTracer, error) {
	logFile, _ := os.Create("records/rss_memory")
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickResidentMemory, logger: logger}, nil
}

func NewDataVirtualMemoryTracer(proc *procfs.Proc) (SystemTracer, error) {
	logFile, _ := os.Create("records/data_memory")
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickDataVirtualMemory, logger: logger}, nil
}

func NewSTimeTracer(proc *procfs.Proc) (SystemTracer, error) {
	logFile, _ := os.Create("records/s_time")
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickSTime, logger: logger}, nil
}

func NewUTimeTracer(proc *procfs.Proc) (SystemTracer, error) {
	logFile, _ := os.Create("records/u_time")
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickUTime, logger: logger}, nil
}

func NewCSTimeTracer(proc *procfs.Proc) (SystemTracer, error) {
	logFile, _ := os.Create("records/cs_time")
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickCSTime, logger: logger}, nil
}

func NewCUTimeTracer(proc *procfs.Proc) (SystemTracer, error) {
	logFile, _ := os.Create("records/cu_time")
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickCUTime, logger: logger}, nil
}

func tickDiskRead(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	readBytes := stat.ReadBytes
	logData := fmt.Sprintf("%d,%d", GetEventTime(t), readBytes)
	tracer.logger.Log().Str("r", logData).Msg("")
}

func tickDiskWrite(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	writeBytes := stat.WriteBytes
	logData := fmt.Sprintf("%d,%d", GetEventTime(t), writeBytes)
	tracer.logger.Log().Str("r", logData).Msg("")
}

func tickVirtualMemory(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedVm := uint64(stat.VirtualMemory())
	logData := fmt.Sprintf("%d,%d", GetEventTime(t), allocatedVm)
	tracer.logger.Log().Str("r", logData).Msg("")
}

func tickResidentMemory(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedRss := uint64(stat.ResidentMemory())
	logData := fmt.Sprintf("%d,%d", GetEventTime(t), allocatedRss)
	tracer.logger.Log().Str("r", logData).Msg("")
}

func tickDataVirtualMemory(t time.Time, tracer *SystemTracer) {
	status, _ := tracer.proc.NewStatus()
	allocatedVmData := uint64(status.VmData)
	logData := fmt.Sprintf("%d,%d", GetEventTime(t), allocatedVmData)
	tracer.logger.Log().Str("r", logData).Msg("")
}

func tickCSTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedCSTime := uint64(stat.CSTime)
	logData := fmt.Sprintf("%d,%d", GetEventTime(t), recordedCSTime)
	tracer.logger.Log().Str("r", logData).Msg("")
}

func tickCUTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedCUTime := uint64(stat.CUTime)
	logData := fmt.Sprintf("%d,%d", GetEventTime(t), recordedCUTime)
	tracer.logger.Log().Str("r", logData).Msg("")
}

func tickSTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedSTime := uint64(stat.STime)
	logData := fmt.Sprintf("%d,%d", GetEventTime(t), recordedSTime)
	tracer.logger.Log().Str("r", logData).Msg("")
}

func tickUTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedUTime := uint64(stat.UTime)
	logData := fmt.Sprintf("%d,%d", GetEventTime(t), recordedUTime)
	tracer.logger.Log().Str("r", logData).Msg("")
}

func (systemTracer SystemTracer) Start(ticker time.Ticker, stop chan bool) {
	for {
		select {
		case t := <-ticker.C:
			systemTracer.ticker(t, &systemTracer)
		case <-stop:
			return
		}
	}
}
