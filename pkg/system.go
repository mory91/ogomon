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

func GetTargetProc(name string, pid int) (procfs.Proc, error) {
	if pid != -1 {
		var proc procfs.Proc
		proc, err := procfs.NewProc(pid)
		if err != nil {
			jww.ERROR.Println(err)
			return proc, err
		}
		return proc, nil
	} else {
		procs, err := procfs.AllProcs()
		var targetProc procfs.Proc
		found := false
		ogomon := false
		if err != nil {
			return procfs.Proc{}, err
		}
		for _, p := range procs {
			cmdParts, _ := p.CmdLine()
			ogomon = false
			for _, cmdPart := range cmdParts {
				if strings.Index(cmdPart, name) >= 0  {
					targetProc = p
					found = true
				}
				if strings.Index(cmdPart, "ogomon") >= 0 {
					ogomon = true
					break
				}
			}
			if found && !ogomon {
				return targetProc, nil
			}
		}
		if found && !ogomon {
			return targetProc, nil
		}
		return targetProc, fmt.Errorf("NOT FOUND")
	}
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

func CreateProcessAndPipeToFile(cmd *exec.Cmd, filename string, appendFile bool) {
	var logFile *os.File
	var err error
	if !appendFile {
		logFile, err = os.Create(filename)
		if err != nil {
			panic(err)
		}
	} else {
		logFile, _ = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			panic(err)
		}
	}

	defer logFile.Close()
	cmd.Stdout = logFile
	var errbuf strings.Builder
	cmd.Stderr = &errbuf
	err = cmd.Start()
	if err != nil {
		panic(err)
	}
	cmd.Wait()
}
