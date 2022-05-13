package cmd

import (
	"fmt"
	"github.com/prometheus/procfs"
	"github.com/spf13/cobra"
	jww "github.com/spf13/jwalterweatherman"
	"ogomon/pkg/system"
	"time"
)

type Monitor struct {
	proc procfs.Proc
}

func (m Monitor) Start() error {
	stat, _ := m.proc.Stat()
	jww.INFO.Printf("PID: %d", stat.PID)
	jww.INFO.Printf("Executable Name: %s", stat.Comm)

	var prevSizeVm uint = 0
	var prevSizeIOReadBytes uint64 = 0
	var prevSizeIOWriteBytes uint64 = 0
	for {
		stat, _ := m.proc.Stat()
		io, _ := m.proc.IO()
		allocatedVm := stat.VSize - prevSizeVm
		allocatedReadBytes := io.ReadBytes - prevSizeIOReadBytes
		allocatedWriteBytes := io.WriteBytes - prevSizeIOWriteBytes
		jww.INFO.Println(fmt.Sprintf("%d %d %d %d", allocatedVm, allocatedReadBytes, allocatedWriteBytes, time.Now().UnixMilli()))
		prevSizeVm = stat.VSize
		prevSizeIOReadBytes = io.ReadBytes
		prevSizeIOWriteBytes = io.WriteBytes
		time.Sleep(time.Millisecond * 10)
	}

	return nil
}

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "memory and disk",
	RunE: func(cmd *cobra.Command, args []string) error {
		jww.INFO.Println("Monitor Starting")
		proc, _ := system.GetTargetProc(executableName)
		m := Monitor{proc: proc}
		if err := m.Start(); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)
}
