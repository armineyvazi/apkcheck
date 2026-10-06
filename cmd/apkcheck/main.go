package main

import (
	"os"

	"github.com/armin/apkcheck/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
