package pkg

import (
	"encoding/binary"
	"os"
	"fmt"
	"os/exec"
	"strings"
	"unsafe"

	procfs "github.com/prometheus/procfs"
	"golang.org/x/sys/unix"
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

func CreateProcessAndPipeToFile(cmd *exec.Cmd, filename string) {
	outfile, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer outfile.Close()
	cmd.Stdout = outfile
	err = cmd.Start()
	if err != nil {
		panic(err)
	}
	cmd.Wait()
}