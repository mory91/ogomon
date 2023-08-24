package internal

import (
	"bufio"
	"fmt"
	"os"
	"runtime/trace"
	"time"

	"github.com/prometheus/procfs"
)

const (
	SYS_STAT_STEP        = 250
	SYS_STAT_TICKER_TIME = time.Microsecond * SYS_STAT_STEP
)


type DataTicker func(tracer *SystemTracer) uint64

type SystemTracer struct {
	proc         *procfs.Proc
	fs           *procfs.FS
	ticker       DataTicker
	tickerTime   time.Duration
	logFile      *os.File
	writer       *bufio.Writer
	isStop       bool
}

func NewMemAvaibaleTracer(fs *procfs.FS, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/memavailable")
	} else {
		logFile, _ = os.OpenFile("records/memavailable", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 16384)
	return &SystemTracer{fs: fs, ticker: tickMemAvailable, writer: writer, tickerTime: SYS_STAT_TICKER_TIME, logFile: logFile}, nil
}

func NewNetTCPV6Tracer(fs *procfs.FS, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/TXQ6")
	} else {
		logFile, _ = os.OpenFile("records/TXQ6", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 16384)
	return &SystemTracer{fs: fs, ticker: tickTXQueueV6, writer: writer, tickerTime: SYS_STAT_TICKER_TIME, logFile: logFile}, nil
}

func NewNetTCPTracer(fs *procfs.FS, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/TXQ")
	} else {
		logFile, _ = os.OpenFile("records/TXQ", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 16384)
	return &SystemTracer{fs: fs, ticker: tickTXQueue, writer: writer, tickerTime: SYS_STAT_TICKER_TIME, logFile: logFile}, nil
}

func NewDiskReadTracer(proc *procfs.Proc, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/disk_read")
	} else {
		logFile, _ = os.OpenFile("records/disk_read", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 8192)
	return &SystemTracer{proc: proc, ticker: tickDiskRead, writer: writer, tickerTime: SYS_STAT_TICKER_TIME, logFile: logFile}, nil
}

func NewDiskWriteTracer(proc *procfs.Proc, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/disk_write")
	} else {
		logFile, _ = os.OpenFile("records/disk_write", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 8192)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickDiskWrite, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewMemoryTracer(proc *procfs.Proc, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/memory")
	} else {
		logFile, _ = os.OpenFile("records/memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 8192)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickVirtualMemory, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewResidentMemoryTracer(proc *procfs.Proc, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/rss_memory")
	} else {
		logFile, _ = os.OpenFile("records/rss_memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 8192)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickResidentMemory, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewDataVirtualMemoryTracer(proc *procfs.Proc, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/data_memory")
	} else {
		logFile, _ = os.OpenFile("records/data_memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 8192)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickDataVirtualMemory, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewSTimeTracer(proc *procfs.Proc, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/s_time")
	} else {
		logFile, _ = os.OpenFile("records/s_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 8192)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickSTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewUTimeTracer(proc *procfs.Proc, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/u_time")
	} else {
		logFile, _ = os.OpenFile("records/u_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 8192)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickUTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewCSTimeTracer(proc *procfs.Proc, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/cs_time")
	} else {
		logFile, _ = os.OpenFile("records/cs_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 8192)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickCSTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewCUTimeTracer(proc *procfs.Proc, appendFile bool) (*SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/cu_time")
	} else {
		logFile, _ = os.OpenFile("records/cu_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriterSize(logFile, 8192)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickCUTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func tickMemAvailable(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	stat, _ := tracer.fs.Meminfo()
	memAvailable := stat.MemAvailable
	logData := fmt.Sprintf("%d,%d\n", evTime, memAvailable)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickDiskRead(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	stat, _ := tracer.proc.IO()
	readBytes := stat.ReadBytes
	logData := fmt.Sprintf("%d,%d\n", evTime, readBytes)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickDiskWrite(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	stat, _ := tracer.proc.IO()
	writeBytes := stat.WriteBytes
	logData := fmt.Sprintf("%d,%d\n", evTime, writeBytes)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickVirtualMemory(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	stat, _ := tracer.proc.Stat()
	allocatedVm := uint64(stat.VirtualMemory())
	logData := fmt.Sprintf("%d,%d\n", evTime, allocatedVm)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickResidentMemory(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	stat, _ := tracer.proc.Stat()
	allocatedRss := uint64(stat.ResidentMemory())
	logData := fmt.Sprintf("%d,%d\n", evTime, allocatedRss)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickDataVirtualMemory(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	status, _ := tracer.proc.NewStatus()
	allocatedVmData := uint64(status.VmData)
	logData := fmt.Sprintf("%d,%d\n", evTime, allocatedVmData)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickCSTime(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	stat, _ := tracer.proc.Stat()
	recordedCSTime := uint64(stat.CSTime)
	logData := fmt.Sprintf("%d,%d\n", evTime, recordedCSTime)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickCUTime(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	stat, _ := tracer.proc.Stat()
	recordedCUTime := uint64(stat.CUTime)
	logData := fmt.Sprintf("%d,%d\n", evTime, recordedCUTime)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickSTime(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	stat, _ := tracer.proc.Stat()
	recordedSTime := uint64(stat.STime)
	logData := fmt.Sprintf("%d,%d\n", evTime, recordedSTime)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickUTime(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	stat, _ := tracer.proc.Stat()
	recordedUTime := uint64(stat.UTime)
	logData := fmt.Sprintf("%d,%d\n", evTime, recordedUTime)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickTXQueue(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	summary, _ := tracer.fs.NetTCPSummary()
	TXQLen := uint64(summary.TxQueueLength)
	logData := fmt.Sprintf("%d,%d\n", evTime, TXQLen)
	tracer.writer.WriteString(logData)
	return evTime
}

func tickTXQueueV6(tracer *SystemTracer) uint64 {
	evTime := GetEventTime()
	summary, _ := tracer.fs.NetTCP6Summary()
	TXQLen := uint64(summary.TxQueueLength)
	logData := fmt.Sprintf("%d,%d\n", evTime, TXQLen)
	tracer.writer.WriteString(logData)
	return evTime
}

func (systemTracer *SystemTracer) Start() {
	for {
		var t1 uint64
		if !systemTracer.isStop {
			t1 = systemTracer.ticker(systemTracer)
		} else {
			systemTracer.TearDown()
			break
		}
		d := (uint64(time.Now().UnixNano()) - t1) / 1000
		time.Sleep(time.Duration(SYS_STAT_STEP - d) * time.Microsecond)
	}
}

func (systemTracer SystemTracer) GetTickerTime() time.Duration {
	return systemTracer.tickerTime
}

func (systemTracer *SystemTracer) TearDown() {
	systemTracer.writer.Flush()
	systemTracer.logFile.Close()
}

func (systemTracer *SystemTracer) Stop() {
	systemTracer.isStop = true
}
