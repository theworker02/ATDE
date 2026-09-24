package doctor

import (
	"testing"

	"github.com/theworker02/ATDE/v2/internal/config"
)

func TestRunBasic(t *testing.T) {
	cfg := &config.Config{}
	cfg.App.OpsAddr = ":0"
	cfg.Ingest.Honeypot.HTTPAddr = ":0"
	cfg.Ingest.Honeypot.SSHAddr = ":0"
	cfg.Deception.ListenAddr = ":0"
	cfg.NATS.URL = "nats://127.0.0.1:1"
	checks := Run(cfg)
	if len(checks) < 3 {
		t.Fatalf("expected checks, got %d", len(checks))
	}
	_ = ExitCode(checks)
}
