package pkg

import (
	"encoding/binary"
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
	"os"
	"os/exec"
	"strings"
	"unsafe"

	procfs "github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
)

func GetTargetProc(name string) (procfs.Proc, error) {
	procs, err := procfs.AllProcs()
	maxPID := -1
	var targetProc procfs.Proc
	if err != nil {
		return procfs.Proc{}, err
	}
	for _, p := range procs {
		comm, _ := p.Comm()
		if strings.Index(comm, name) >= 0 && p.PID > maxPID {
			maxPID = p.PID
			targetProc = p
		}
	}
	if maxPID == -1 {
		return targetProc, fmt.Errorf("NOT FOUND")
	}
	return targetProc, nil
}

func OpenMemLock() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		jww.WARN.Println("Failed to adjust rlimit: ", err)
	}
}

func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func CreateProcessAndPipeToFile(cmd *exec.Cmd, filename string) {
	outfile, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer outfile.Close()
	cmd.Stdout = outfile
	var errbuf strings.Builder
	cmd.Stderr = &errbuf
	err = cmd.Start()
	if err != nil {
		panic(err)
	}
	cmd.Wait()
}
