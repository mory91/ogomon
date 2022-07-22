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

	"github.com/prometheus/procfs"
	"github.com/spf13/cobra"
	jww "github.com/spf13/jwalterweatherman"
)

type Monitor struct {
	proc procfs.Proc
}

var (
	deviceName string
	srcPort    int
	destPort   int
	wg         sync.WaitGroup
)

const (
	STEP = 500
	TICKER_TIME = time.Microsecond * STEP
)

func (m Monitor) Start() error {
	stat, _ := m.proc.Stat()
	jww.INFO.Printf("PID: %d", stat.PID)
	jww.INFO.Printf("Executable Name: %s", stat.Comm)

	stop := make(chan bool)
	stopCount := 0

	cancelSig := make(chan os.Signal, 1)
	signal.Notify(cancelSig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	socketTracer, err := ebpf.NewFilterSocketTracer(deviceName, srcPort, destPort)
	if err != nil {
		jww.ERROR.Fatalln(err)
	}
	diskReadTracer, err := internal.NewDiskReadTracer(&m.proc)
	diskWriteTracer, err := internal.NewDiskWriteTracer(&m.proc)

	tracers := []internal.Tracer{diskWriteTracer, diskReadTracer, socketTracer}
	names := []string{"disk_write", "disk_read", "packets"}

	var tickers []*time.Ticker

	for idx, _ := range tracers {
		stopCount++
		wg.Add(2)
		tmpTracer := idx

		ticker := time.NewTicker(TICKER_TIME)
		tickers = append(tickers, ticker)

		go func() {
			defer wg.Done()
			tracers[tmpTracer].Start(*ticker, stop)
		}()
		go func() {
			defer wg.Done()
			internal.LogTrace(tracers[tmpTracer].Chan(), fmt.Sprintf("%s", names[tmpTracer]))
		}()
	}

	// memory allocations section
	command := exec.Command("sudo", "./mem.py", "-p", fmt.Sprintf("%d", stat.PID), "-s", strconv.FormatInt(TICKER_TIME.Nanoseconds(), 10))
	go func (cmd *exec.Cmd)  {
    	outfile, err := os.Create("./allocations")
    	if err != nil {
      		panic(err)
    	}
    	defer outfile.Close()
    	cmd.Stdout = outfile
    	err = cmd.Start(); if err != nil {
        	panic(err)
    	}
    	cmd.Wait()
	}(command)
	// end memory allocation

	if err != nil {
		panic(err)
	}

	<-cancelSig

	command.Process.Signal(syscall.SIGTERM)

	for _, t := range tickers {
		t.Stop()
	}
	for i := 0; i < stopCount; i++ {
		stop <- true
	}
	wg.Wait()
	return nil
}

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "memory and disk",
	RunE: func(cmd *cobra.Command, args []string) error {
		jww.INFO.Println("Monitor Starting")
		proc, _ := pkg.GetTargetProc(executableName)
		m := Monitor{proc: proc}
		if err := m.Start(); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	monitorCmd.Flags().StringVarP(&deviceName, "device-name", "d", "", "Interface Name")
	monitorCmd.Flags().IntVarP(&srcPort, "src-port", "s", 0, "Set Source Port")
	monitorCmd.Flags().IntVarP(&destPort, "dest-port", "t", 0, "Set Destination Port")
	rootCmd.AddCommand(monitorCmd)
}
