// Command adk scans a project folder for security problems.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/iimmuunnee/ai-defense-kit/internal/cli"
)

// stopSignals end a run cleanly.
var stopSignals = []os.Signal{os.Interrupt, syscall.SIGTERM}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), stopSignals...)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
