package main

import (
	jww "github.com/spf13/jwalterweatherman"
	"ogomon/cmd"
)

func main() {
	jww.SetLogThreshold(jww.LevelTrace)
	jww.SetStdoutThreshold(jww.LevelInfo)
	cmd.Execute()
}
