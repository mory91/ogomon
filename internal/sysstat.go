package internal

import (
	"fmt"
	"os"
	"time"

	"github.com/prometheus/procfs"
	"github.com/rs/zerolog"
)

const (
	SYS_STAT_STEP        = 500
	SYS_STAT_TICKER_TIME = time.Microsecond * SYS_STAT_STEP
)


type DataTicker func(t time.Time, tracer *SystemTracer)

type SystemTracer struct {
	proc         *procfs.Proc
	ticker       DataTicker
	logger       zerolog.Logger
	tickerTime   time.Duration
}

func NewDiskReadTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/disk_read")
	} else {
		logFile, _ = os.OpenFile("records/disk_read", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickDiskRead, logger: logger, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewDiskWriteTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/disk_write")
	} else {
		logFile, _ = os.OpenFile("records/disk_write", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickDiskWrite, logger: logger, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewMemoryTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/memory")
	} else {
		logFile, _ = os.OpenFile("records/memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickVirtualMemory, logger: logger, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewResidentMemoryTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/rss_memory")
	} else {
		logFile, _ = os.OpenFile("records/rss_memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickResidentMemory, logger: logger, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewDataVirtualMemoryTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/data_memory")
	} else {
		logFile, _ = os.OpenFile("records/data_memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickDataVirtualMemory, logger: logger, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewSTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/s_time")
	} else {
		logFile, _ = os.OpenFile("records/s_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickSTime, logger: logger, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewUTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/u_time")
	} else {
		logFile, _ = os.OpenFile("records/u_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickUTime, logger: logger, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewCSTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/cs_time")
	} else {
		logFile, _ = os.OpenFile("records/cs_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickCSTime, logger: logger, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewCUTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/cu_time")
	} else {
		logFile, _ = os.OpenFile("records/cu_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	logger := zerolog.New(logFile)
	return SystemTracer{proc: proc, ticker: tickCUTime, logger: logger, tickerTime: SYS_STAT_TICKER_TIME}, nil
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

func (systemTracer SystemTracer) GetTickerTime() time.Duration {
	return systemTracer.tickerTime
}
