package cmd

import (
	"github.com/spf13/cobra"
	jww "github.com/spf13/jwalterweatherman"
	"os"
)

var executableName string

var rootCmd = &cobra.Command{
	Use:   "ogomon",
	Short: "Monitor system",
}

func Execute() {
	rootCmd.PersistentFlags().StringVarP(&executableName, "executable", "e", "", "Name to trace")
	if err := rootCmd.Execute(); err != nil {
		jww.ERROR.Println(err)
		os.Exit(1)
	}
}
