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
		_, err := f.WriteString(fmt.Sprintf("%s\t%s\n", strconv.FormatUint(trace.TS, 10), strconv.FormatUint(trace.Data, 10)))
		if err != nil {
			jww.ERROR.Println(err)
		}
	}
}
