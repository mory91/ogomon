package cmd

import (
	"fmt"
	"ogomon/internal"
	"ogomon/internal/ebpf"
	"ogomon/pkg"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
	"errors"

	"github.com/prometheus/procfs"
	"github.com/spf13/cobra"
	jww "github.com/spf13/jwalterweatherman"
)

type Monitor struct {
	proc procfs.Proc
	cancelChan chan bool
}

var (
	deviceName	   string
	srcPort    	   int
	destPort   	   int
	executableName	   string
	pid		   int
	wg		   sync.WaitGroup
	controlWg	   sync.WaitGroup
)

func (m Monitor) Start(appendFile bool) error {
	stat, _ := m.proc.Stat()
	jww.INFO.Printf("PID: %d", stat.PID)
	jww.INFO.Printf("Executable Name: %s", stat.Comm)

	stop := make(chan bool)
	stopCount := 0


	packetCaptureTracer, err := ebpf.NewPacketCaptureTracer(deviceName, appendFile)
	socketTracer, err := ebpf.NewFilterSocketTracer(deviceName, srcPort, destPort, appendFile)
	if err != nil {
		jww.ERROR.Fatalln(err)
	}
	diskReadTracer, err := internal.NewDiskReadTracer(&m.proc, appendFile)
	diskWriteTracer, err := internal.NewDiskWriteTracer(&m.proc, appendFile)
	memoryTracer, err := internal.NewMemoryTracer(&m.proc, appendFile)
	residentMemoryTracer, err := internal.NewResidentMemoryTracer(&m.proc, appendFile)
	dataVirtualMemoryTracer, err := internal.NewDataVirtualMemoryTracer(&m.proc, appendFile)
	CSTimeTrace, err := internal.NewCSTimeTracer(&m.proc, appendFile)
	CUTimeTrace, err := internal.NewCUTimeTracer(&m.proc, appendFile)
	STimeTracer, err := internal.NewSTimeTracer(&m.proc, appendFile)
	UTimeTracer, err := internal.NewUTimeTracer(&m.proc, appendFile)

	tracers := []internal.Tracer{diskWriteTracer, diskReadTracer, socketTracer, residentMemoryTracer, memoryTracer, dataVirtualMemoryTracer, CSTimeTrace, CUTimeTrace, STimeTracer, UTimeTracer}

	var tickers []*time.Ticker

	go packetCaptureTracer.Start(stop)

	for idx, _ := range tracers {
		stopCount++
		wg.Add(1)
		tmpTracer := idx

		ticker := time.NewTicker(tracers[tmpTracer].GetTickerTime())
		tickers = append(tickers, ticker)

		go func() {
			defer wg.Done()
			tracers[tmpTracer].Start(*ticker, stop)
		}()
	}

	// external commands section
	cpuMemCommand := exec.Command("sudo", "./python/cpu_mem.py", "-p", fmt.Sprintf("%d", stat.PID), "-s", strconv.FormatInt(memoryTracer.GetTickerTime().Nanoseconds(), 10))
	cudaMemCommand := exec.Command("sudo", "./python/cuda_mem.py", "-p", fmt.Sprintf("%d", stat.PID), "-s", strconv.FormatInt(memoryTracer.GetTickerTime().Nanoseconds(), 10))
	sendCommand := exec.Command("sudo", "./python/send.py", "-p", fmt.Sprintf("%d", stat.PID))
	kcacheCommand := exec.Command("sudo", "./python/kcache.py", "-p", fmt.Sprintf("%d", stat.PID))
	go pkg.CreateProcessAndPipeToFile(cpuMemCommand, "./records/cpu_allocations", appendFile)
	go pkg.CreateProcessAndPipeToFile(cudaMemCommand, "./records/cuda_allocations", appendFile)
	go pkg.CreateProcessAndPipeToFile(sendCommand, "./records/sends", appendFile)
	go pkg.CreateProcessAndPipeToFile(kcacheCommand, "./records/kcache", appendFile)
	// external commands section

	if err != nil {
		panic(err)
	}

	<-m.cancelChan
	
	cpuMemCommand.Process.Kill()
	sendCommand.Process.Kill()
	cudaMemCommand.Process.Kill()
	kcacheCommand.Process.Kill()

	for _, t := range tickers {
		t.Stop()
	}
	packetCaptureTracer.TearDown()
	for i := 0; i < stopCount; i++ {
		stop <- true
	}
	wg.Wait()
	controlWg.Done()
	return nil
}

func monitorProcess(proc procfs.Proc, cancelChan chan bool, appendFile bool) error {
	m := Monitor{proc: proc, cancelChan: cancelChan}
	if err := m.Start(appendFile); err != nil {
		return err
	}
	return nil
}

func newOgomon(exeName string, pid int, notFoundChan chan bool, cancelChan chan bool, appendFile bool) {
	proc, err := pkg.GetTargetProc(exeName, pid)
	found := false
	if err != nil {
		found = false
		for c := 0; c < 3; c++ {
			proc, err = pkg.GetTargetProc(exeName, pid)
			if err == nil {
				found = true
				break
			} else {
				jww.ERROR.Println(err)
				time.Sleep(1 * time.Second)
			}
		}
		if !found {
			os.Exit(1)
		}
	}
	go func(process procfs.Proc) {
		var errTarget *os.PathError
		for {
			_, err := process.Comm()
			if err != nil && errors.As(err, &errTarget) {
				notFoundChan <- true
				jww.INFO.Println("Process Closed")
				break
			}
		}
	}(proc)
	go monitorProcess(proc, cancelChan, appendFile)
}

func ogomonControl(exeName string, pid int) {
	dieSignalChan := make(chan os.Signal)
	notFoundChan := make(chan bool)
	signal.Notify(dieSignalChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	cancelChan := make(chan bool)
	controlWg.Add(1)
	newOgomon(exeName, pid, notFoundChan, cancelChan, false)
	LOOP:
	for {
		select {
		case <- dieSignalChan:
			cancelChan <- true
			close(dieSignalChan)
			close(notFoundChan)
			// WAIT FOR OGOMONG TO END
			controlWg.Wait()
			break LOOP
		case <- notFoundChan:
			cancelChan <- true
			newOgomon(exeName, pid, notFoundChan, cancelChan, true)
			
		}
	}
}

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "memory and disk",
	RunE: func(cmd *cobra.Command, args []string) error {
		jww.INFO.Println("Monitor Starting")
		if pid == -1 && executableName == "NOTSET" {
			jww.ERROR.Println("NO PID AND EXE")
			os.Exit(1)
		}
		ogomonControl(executableName, pid)
		return nil
	},
}

func init() {
	monitorCmd.Flags().StringVarP(&deviceName, "device-name", "d", "", "Interface Name")
	monitorCmd.Flags().IntVarP(&srcPort, "src-port", "s", 0, "Set Source Port")
	monitorCmd.Flags().IntVarP(&destPort, "dest-port", "t", 0, "Set Destination Port")
	monitorCmd.Flags().StringVarP(&executableName, "executable", "e", "NOTSET", "Name to trace")
	monitorCmd.Flags().IntVarP(&pid, "pid", "p", -1, "PID to trace")
	rootCmd.AddCommand(monitorCmd)
}
