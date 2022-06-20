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
			sport, dport, length := nt.Sport, nt.Dport, nt.Len
			data = fmt.Sprintf(
				"%s\t%s\t%s\t",
				strconv.FormatUint(length, 10),
				strconv.FormatUint(sport, 10),
				strconv.FormatUint(dport, 10),
			)
		}
		_, err := f.WriteString(fmt.Sprintf("%s\t%s\n", strconv.FormatUint(trace.TS, 10), data))
		if err != nil {
			jww.ERROR.Println(err)
		}
	}
}
