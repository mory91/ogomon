package pkg

import (
	"encoding/binary"
	"fmt"
	procfs "github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
	"strings"
	"unsafe"
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

func OpenMemLock() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		fmt.Println("WARNING: Failed to adjust rlimit: ", err)
	}
}

func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
