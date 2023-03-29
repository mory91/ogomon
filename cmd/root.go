package cmd

import (
	"os"
	"github.com/spf13/cobra"
	jww "github.com/spf13/jwalterweatherman"
)


var rootCmd = &cobra.Command{
	Use:   "ogomon",
	Short: "Monitor system",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		jww.ERROR.Println(err)
		os.Exit(1)
	}
}
