//go:build !linux

package harden

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"time"
)

func checkTracerPID() (string, bool) { return "", false }

func checkPtrace() (string, bool) { return "", false }

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
		return fmt.Sprintf("Execution latency anomaly (>%s)", threshold), true
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

func disableDumpable() error { return nil }

func killSelf() {
	os.Exit(137)
}
