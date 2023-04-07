package internal

import (
	"bufio"
	"fmt"
	"os"
	"time"

	"github.com/prometheus/procfs"
)

const (
	SYS_STAT_STEP        = 50
	SYS_STAT_TICKER_TIME = time.Microsecond * SYS_STAT_STEP
)


type DataTicker func(t time.Time, tracer *SystemTracer)

type SystemTracer struct {
	proc         *procfs.Proc
	ticker       DataTicker
	tickerTime   time.Duration
	logFile      *os.File
	writer       *bufio.Writer
}

func NewDiskReadTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/disk_read")
	} else {
		logFile, _ = os.OpenFile("records/disk_read", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return SystemTracer{proc: proc, ticker: tickDiskRead, writer: writer, tickerTime: SYS_STAT_TICKER_TIME, logFile: logFile}, nil
}

func NewDiskWriteTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/disk_write")
	} else {
		logFile, _ = os.OpenFile("records/disk_write", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return SystemTracer{proc: proc, logFile: logFile, ticker: tickDiskWrite, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewMemoryTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/memory")
	} else {
		logFile, _ = os.OpenFile("records/memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return SystemTracer{proc: proc, logFile: logFile, ticker: tickVirtualMemory, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewResidentMemoryTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/rss_memory")
	} else {
		logFile, _ = os.OpenFile("records/rss_memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return SystemTracer{proc: proc, logFile: logFile, ticker: tickResidentMemory, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewDataVirtualMemoryTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/data_memory")
	} else {
		logFile, _ = os.OpenFile("records/data_memory", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return SystemTracer{proc: proc, logFile: logFile, ticker: tickDataVirtualMemory, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewSTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/s_time")
	} else {
		logFile, _ = os.OpenFile("records/s_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return SystemTracer{proc: proc, logFile: logFile, ticker: tickSTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewUTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/u_time")
	} else {
		logFile, _ = os.OpenFile("records/u_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return SystemTracer{proc: proc, logFile: logFile, ticker: tickUTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewCSTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/cs_time")
	} else {
		logFile, _ = os.OpenFile("records/cs_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return SystemTracer{proc: proc, logFile: logFile, ticker: tickCSTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func NewCUTimeTracer(proc *procfs.Proc, appendFile bool) (SystemTracer, error) {
	var logFile *os.File
	if !appendFile {
		logFile, _ = os.Create("records/cu_time")
	} else {
		logFile, _ = os.OpenFile("records/cu_time", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	}
	writer := bufio.NewWriter(logFile)
	return SystemTracer{proc: proc, logFile: logFile, ticker: tickCUTime, writer: writer, tickerTime: SYS_STAT_TICKER_TIME}, nil
}

func tickDiskRead(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	readBytes := stat.ReadBytes
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(t), readBytes)
	tracer.writer.WriteString(logData)
}

func tickDiskWrite(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.IO()
	writeBytes := stat.WriteBytes
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(t), writeBytes)
	tracer.writer.WriteString(logData)
}

func tickVirtualMemory(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedVm := uint64(stat.VirtualMemory())
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(t), allocatedVm)
	tracer.writer.WriteString(logData)
}

func tickResidentMemory(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	allocatedRss := uint64(stat.ResidentMemory())
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(t), allocatedRss)
	tracer.writer.WriteString(logData)
}

func tickDataVirtualMemory(t time.Time, tracer *SystemTracer) {
	status, _ := tracer.proc.NewStatus()
	allocatedVmData := uint64(status.VmData)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(t), allocatedVmData)
	tracer.writer.WriteString(logData)
}

func tickCSTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedCSTime := uint64(stat.CSTime)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(t), recordedCSTime)
	tracer.writer.WriteString(logData)
}

func tickCUTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedCUTime := uint64(stat.CUTime)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(t), recordedCUTime)
	tracer.writer.WriteString(logData)
}

func tickSTime(t time.Time, tracer *SystemTracer) {
	stat, _ := tracer.proc.Stat()
	recordedSTime := uint64(stat.STime)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(t), recordedSTime)
	tracer.writer.WriteString(logData)
}

func tickUTime(t time.Time, tracer *SystemTracer) {
	t1 := time.Now()
	stat, _ := tracer.proc.Stat()
	recordedUTime := uint64(stat.UTime)
	logData := fmt.Sprintf("%d,%d\n", GetEventTime(t), recordedUTime)
	tracer.writer.WriteString(logData)
	fmt.Println(time.Since(t1).Milliseconds())
}

func (systemTracer SystemTracer) Start(ticker time.Ticker, stop chan bool) {
	for {
		select {
		case t := <-ticker.C:
			systemTracer.ticker(t, &systemTracer)
		case <-stop:
			systemTracer.TearDown()
			return
		}
	}
}

func (systemTracer SystemTracer) GetTickerTime() time.Duration {
	return systemTracer.tickerTime
}

func (systemTracer SystemTracer) TearDown() {
	systemTracer.writer.Flush()
	systemTracer.logFile.Close()
}
