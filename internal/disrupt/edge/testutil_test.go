package edge

import (
	"io"
	"log/slog"

	"github.com/theworker02/blind-botnet/v2/internal/config"
)

func testEdgeCfg(local bool) config.EdgeConfig {
	return config.EdgeConfig{
		Enabled:       true,
		DryRun:        true,
		LocalFirewall: local,
	}
}

func testLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
