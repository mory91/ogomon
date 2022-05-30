package pkg

import (
	jww "github.com/spf13/jwalterweatherman"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	NANOSECSINSEC = 1000000000
)

func GetMonoTime() uint64 {
	var ts syscall.Timespec
	_, _, err := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, unix.CLOCK_MONOTONIC, uintptr(unsafe.Pointer(&ts)), 0)
	if err != 0 {
		jww.INFO.Println(err)
	}
	return uint64(ts.Sec)*NANOSECSINSEC + uint64(ts.Nsec)
}
