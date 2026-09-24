//go:build !linux

package harden

import "log/slog"

func ApplySeccompSandbox(log *slog.Logger) error {
	if log != nil {
		log.Info("seccomp skipped (non-linux)")
	}
	return nil
}
