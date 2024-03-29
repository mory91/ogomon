package internal

import "time"

type Tracer interface {
	Start()
	Stop()
	GetTickerTime() time.Duration
	TearDown()
}
type Trace struct {
	Data interface{}
	TS   uint64
}
type NetworkTrace struct {
	Len       uint64
	Sport     uint64
	Dport     uint64
	Saddr     uint64
	Daddr     uint64
	Direction uint64
}
