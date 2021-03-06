package internal

import (
	"fmt"
	jww "github.com/spf13/jwalterweatherman"
	"os"
	"strconv"
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
			sport, dport, length, dir := nt.Sport, nt.Dport, nt.Len, nt.Direction
			data = fmt.Sprintf(
				"%s\t%s\t%s\t%s\t",
				strconv.FormatUint(uint64(length), 10),
				strconv.FormatUint(uint64(sport), 10),
				strconv.FormatUint(uint64(dport), 10),
				strconv.FormatUint(uint64(dir), 10),
			)
		}
		_, err := f.WriteString(fmt.Sprintf("%s\t%s\n", strconv.FormatUint(trace.TS, 10), data))
		if err != nil {
			jww.ERROR.Println(err)
		}
	}
}
