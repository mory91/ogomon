package pkg

import (
	jww "github.com/spf13/jwalterweatherman"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
#include <time.h>
static unsigned long long get_nsecs(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000UL + ts.tv_nsec;
}
*/
import "C"

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

func GetBootTime() uint64 {
	return uint64(C.get_nsecs())
}
