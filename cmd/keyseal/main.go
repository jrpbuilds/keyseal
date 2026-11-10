package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/jrpbuilds/keyseal/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		var exitCoder interface{ ExitCode() int }
		if errors.As(err, &exitCoder) {
			if err.Error() != "" {
				fmt.Fprintln(os.Stderr, err)
			}
			os.Exit(exitCoder.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
