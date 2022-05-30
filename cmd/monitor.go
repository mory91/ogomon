package cmd

import (
	"fmt"
	"ogomon/internal"
	"ogomon/internal/ebpf"
	"ogomon/pkg"
	"os"
	"os/signal"
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
	port       int
	wg         sync.WaitGroup
)

func (m Monitor) Start() error {
	stat, _ := m.proc.Stat()
	jww.INFO.Printf("PID: %d", stat.PID)
	jww.INFO.Printf("Executable Name: %s", stat.Comm)
	ticker := time.NewTicker(time.Millisecond * 10)

	stop := make(chan bool)
	stopCount := 0

	cancelSig := make(chan os.Signal, 1)
	signal.Notify(cancelSig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)

	networkInTracer, err := ebpf.NewTcNetworkTracer(deviceName, port, ebpf.INGRESS)
	networkOutTracer, err := ebpf.NewTcNetworkTracer(deviceName, port, ebpf.EGRESS)
	diskReadTracer, err := internal.NewDiskReadTracer(&m.proc)
	diskWriteTracer, err := internal.NewDiskWriteTracer(&m.proc)
	memoryTracer, err := internal.NewMemoryTracer(&m.proc)
	residentMemoryTracer, err := internal.NewResidentMemoryTracer(&m.proc)

	tracers := []internal.Tracer{diskWriteTracer, diskReadTracer, memoryTracer, networkInTracer, networkOutTracer, residentMemoryTracer}
	names := []string{"disk_write", "disk_read", "memory", "network_in", "network_out", "resident_memory"}
	for idx, _ := range tracers {
		stopCount++
		wg.Add(2)
		tmpTracer := idx
		go func() {
			defer wg.Done()
			tracers[tmpTracer].Start(*ticker, stop)
		}()
		go func() {
			defer wg.Done()
			internal.LogTrace(tracers[tmpTracer].Chan(), fmt.Sprintf("%s", names[tmpTracer]))
		}()
	}

	if err != nil {
		panic(err)
	}

	<-cancelSig
	ticker.Stop()
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
	monitorCmd.Flags().IntVarP(&port, "port", "p", 0, "Set Port")
	rootCmd.AddCommand(monitorCmd)
}
