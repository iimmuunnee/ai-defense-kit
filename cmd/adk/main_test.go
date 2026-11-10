package main

import (
	"bytes"
	"os"
	"os/exec"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestMain(m *testing.M) {
	if os.Getenv("ADK_RUN_MAIN") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

// A service manager stops a long --every run with SIGTERM.
func TestStopSignalsIncludeSIGTERM(t *testing.T) {
	if !slices.Contains(stopSignals, os.Signal(syscall.SIGTERM)) || !slices.Contains(stopSignals, os.Interrupt) {
		t.Errorf("stopSignals = %v", stopSignals)
	}
}

func TestUnknownCommandExits2(t *testing.T) {
	cmd := exec.Command(os.Args[0], "bogus")
	cmd.Env = append(os.Environ(), "ADK_RUN_MAIN=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	ee, ok := err.(*exec.ExitError)
	if !ok || ee.ExitCode() != 2 {
		t.Fatalf("want exit 2, got %v", err)
	}
	if !strings.Contains(stderr.String(), "사용법") {
		t.Errorf("no usage: %s", stderr.String())
	}
}
