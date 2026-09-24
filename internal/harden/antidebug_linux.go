//go:build linux

package harden

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func checkTracerPID() (string, bool) {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return "", false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "TracerPid:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return "", false
		}
		pid, _ := strconv.Atoi(parts[1])
		if pid != 0 {
			return fmt.Sprintf("Debugger attached via TracerPid: %d", pid), true
		}
		return "", false
	}
	return "", false
}

var ptraceClaimed bool

func checkPtrace() (string, bool) {
	if ptraceClaimed {
		return "", false
	}
	// PTRACE_TRACEME — if already traced, fails; on success we own the trace slot.
	_, _, errno := unix.Syscall(unix.SYS_PTRACE, unix.PTRACE_TRACEME, 0, 0)
	if errno != 0 {
		return "Ptrace attachment denied (debugger present)", true
	}
	ptraceClaimed = true
	return "", false
}

func checkTimingAnomaly(threshold time.Duration) (string, bool) {
	if threshold <= 0 {
		threshold = 500 * time.Millisecond
	}
	start := time.Now()
	sum := 0
	for i := 0; i < 1_000_000; i++ {
		sum += i
	}
	_ = sum
	if time.Since(start) > threshold {
		return fmt.Sprintf("Execution latency anomaly (>%s) — possible single-stepping", threshold), true
	}
	return "", false
}

func verifySelfBinaryIntegrity(expectedHash string) (string, bool) {
	exePath, err := os.Executable()
	if err != nil {
		return "", false
	}
	f, err := os.Open(exePath)
	if err != nil {
		return "", false
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", false
	}
	got := fmt.Sprintf("%x", h.Sum(nil))
	if expectedHash != "" && got != expectedHash {
		return "Binary integrity mismatch (disk executable tampered)", true
	}
	return "", false
}

func disableDumpable() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func killSelf() {
	_ = unix.Kill(unix.Getpid(), syscall.SIGKILL)
}
