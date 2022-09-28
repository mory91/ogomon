package internal

import (
	"fmt"
	"os"
	"strconv"

	jww "github.com/spf13/jwalterweatherman"
)

func LogTrace(ch chan Trace, filename string) {
	f, err := os.Create(filename)
	if err != nil {
		jww.ERROR.Println(err)
		return
	}
	defer f.Close()
	for trace := range ch {
		var data string
		switch trace.Data.(type) {
		case uint64:
			data = strconv.FormatUint(trace.Data.(uint64), 10)
		case NetworkTrace:
			nt := trace.Data.(NetworkTrace)
			sport, dport, length, dir, saddr, daddr := nt.Sport, nt.Dport, nt.Len, nt.Direction, nt.Saddr, nt.Daddr
			data = fmt.Sprintf(
				"%d,%d,%d,%d,%d,%d", length, saddr, daddr, sport, dport, dir,
			)
		}
		_, err := f.WriteString(fmt.Sprintf("%s,%s\n", strconv.FormatUint(trace.TS, 10), data))
		if err != nil {
			jww.ERROR.Println(err)
		}
	}
	jww.INFO.Println("Syncing file: ", filename)
	f.Sync()
}
