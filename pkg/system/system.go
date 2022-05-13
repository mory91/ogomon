package system

import (
	"fmt"
	procfs "github.com/prometheus/procfs"
	"strings"
)

func GetTargetProc(name string) (procfs.Proc, error) {
	procs, err := procfs.AllProcs()
	if err != nil {
		return procfs.Proc{}, err
	}
	for _, p := range procs {
		comm, _ := p.Comm()
		if strings.Index(comm, name) >= 0 {
			return p, nil
		}
	}
	return procfs.Proc{}, fmt.Errorf("not found")
}
