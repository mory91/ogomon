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
	userLandBaseTime = uint64(time.Now().UnixNano())
	kernelLandBaseTime = pkg.GetMonoTime()
}

func GetEventTime(t time.Time) uint64 {
	return kernelLandBaseTime + (uint64(t.UnixNano()) - userLandBaseTime)
}
