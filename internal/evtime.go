package internal

import (
	"ogomon/pkg"
	"time"
)

var (
	userLandBaseTime   uint64
	kernelLandBaseTime uint64
)

func init() {
	kernelLandBaseTime = pkg.GetMonoTime()
	userLandBaseTime = uint64(time.Now().UnixNano())
}

func GetEventTime() uint64 {
	//return kernelLandBaseTime + (uin 64(t.UnixNano()) - userLandBaseTime)
	return uint64(time.Now().UnixNano())
}
