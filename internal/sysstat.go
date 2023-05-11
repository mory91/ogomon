package internal

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/prometheus/procfs"
)

const (
	SYS_STAT_STEP        = 100
	SYS_STAT_TICKER_TIME = time.Microsecond * SYS_STAT_STEP
)


type DataTicker func(tracer *SystemTracer)

type SystemTracer struct {
	proc         *procfs.Proc
	fs           *procfs.FS
	ticker       DataTicker
	tickerTime   time.Duration
	logFile      *os.File
	writer       *bufio.Writer
	isRunning     bool
}

func NewNetTCPTracer(fs *procfs.FS, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/TXQ")
	} else {
		logFile, _ = os.OpenFile("records/TXQ", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{fs: fs, ticker: tickTXQueue, writer: writer, tickerTime: SYS_STAT_TICKER_TIME, logFile: logFile}, nil
}

func NewDiskReadTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/disk_read")
	} else {
		logFile, _ = os.OpenFile("records/disk_read", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{proc: proc, ticker: tickDiskRead, writer: writer, tickerTime: SYS_STAT_TICKER_TIME, logFile: logFile}, nil
}

func NewDiskWriteTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/disk_write")
	} else {
		logFile, _ = os.OpenFile("records/disk_write", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickDiskWrite, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewMemoryTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/memory")
	} else {
		logFile, _ = os.OpenFile("records/memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickVirtualMemory, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewResidentMemoryTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/rss_memory")
	} else {
		logFile, _ = os.OpenFile("records/rss_memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickResidentMemory, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewDataVirtualMemoryTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/data_memory")
	} else {
		logFile, _ = os.OpenFile("records/data_memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickDataVirtualMemory, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewSTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/s_time")
	} else {
		logFile, _ = os.OpenFile("records/s_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickSTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewUTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/u_time")
	} else {
		logFile, _ = os.OpenFile("records/u_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickUTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewCSTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/cs_time")
	} else {
		logFile, _ = os.OpenFile("records/cs_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickCSTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewCUTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/cu_time")
	} else {
		logFile, _ = os.OpenFile("records/cu_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return &SystemTracer{proc: proc, logFile: logFile, ticker: tickCUTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func tickDiskRead(tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	readBytes := stat.ReadBytes
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), readBytes)
	tracer.writer.WriteString(logData)
}

func tickDiskWrite(tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	writeBytes := stat.WriteBytes
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), writeBytes)
	tracer.writer.WriteString(logData)
}

func tickVirtualMemory(tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedVm := uint64(stat.VirtualMemory())
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), allocatedVm)
	tracer.writer.WriteString(logData)
}

func tickResidentMemory(tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedRss := uint64(stat.ResidentMemory())
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), allocatedRss)
	tracer.writer.WriteString(logData)
}

func tickDataVirtualMemory(tracer *SystemTracer) {
	status, _ := tracer.proc.NewStatus()
	allocatedVmData := uint64(status.VmData)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), allocatedVmData)
	tracer.writer.WriteString(logData)
}

func tickCSTime(tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedCSTime := uint64(stat.CSTime)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), recordedCSTime)
	tracer.writer.WriteString(logData)
}

func tickCUTime(tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedCUTime := uint64(stat.CUTime)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), recordedCUTime)
	tracer.writer.WriteString(logData)
}

func tickSTime(tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedSTime := uint64(stat.STime)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), recordedSTime)
	tracer.writer.WriteString(logData)
}

func tickUTime(tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedUTime := uint64(stat.UTime)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), recordedUTime)
	tracer.writer.WriteString(logData)
}

func tickTXQueue(tracer *SystemTracer) {
	summary, _ := tracer.fs.NetTCPSummary()
	TXQLen := uint64(summary.TxQueueLength)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(), TXQLen)
	tracer.writer.WriteString(logData)
}

func (systemTracer SystemTracer) Start() {
	for {
		if systemTracer.isRunning {
			systemTracer.ticker(&systemTracer)
		} else {
			systemTracer.TearDown()
			break
		}
		time.Sleep(SYS_STAT_TICKER_TIME)
	}
}

func (systemTracer SystemTracer) GetTickerTime() time.Duration {
	return systemTracer.tickerTime
}

func (systemTracer SystemTracer) TearDown() {
	systemTracer.writer.Flush()
	systemTracer.logFile.Close()
}

func (systemTracer *SystemTracer) Stop() {
	systemTracer.isRunning = false
}
