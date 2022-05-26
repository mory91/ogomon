package internal

import "time"

type Tracer interface {
	Start(ticker time.Ticker, stop chan bool)
	Chan() chan Trace
}
type Trace struct {
	Data uint64
	TS   uint64
}
