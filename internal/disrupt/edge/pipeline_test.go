package edge_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/theworker02/blind-botnet/internal/catch"
	"github.com/theworker02/blind-botnet/internal/config"
	"github.com/theworker02/blind-botnet/internal/disrupt/edge"
	"github.com/theworker02/blind-botnet/internal/models"
)

// TestLocalFirstPipeline proves dossier + containment semantics used in diligence demos.
func TestLocalFirstPipeline(t *testing.T) {
	dir := t.TempDir()
	ledger := catch.New(dir)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	blocker := edge.New(config.EdgeConfig{Enabled: true, DryRun: true, LocalFirewall: true}, log)

	ip := "203.0.113.200" // TEST-NET — recorded, not OS-blocked
	_ = ledger.Record(catch.Record{
		Source: "honeypot", IP: ip, Path: "/wp-login.php", Reason: "scanner", Actions: []string{"recorded"},
	})

	res := blocker.EnforceContainment(context.Background(), ip, "honeypot_interaction", 0.9, true)
	if !res.LocalSkipped {
		t.Fatalf("TEST-NET should skip OS block: %+v", res)
	}

	pub := "8.8.8.8"
	res = blocker.EnforceContainment(context.Background(), pub, "honeypot_interaction", 0.9, true)
	if !res.LocalOK {
		t.Fatalf("public dry-run should LocalOK: %+v", res)
	}
	_ = ledger.Record(catch.Record{
		Source: "active", IP: pub, Reason: "honeypot_interaction",
		Actions: []string{"recorded", "local_firewall"}, Blocked: res.LocalOK,
	})

	hits, uniq, err := ledger.Summary()
	if err != nil || hits < 2 || uniq < 2 {
		t.Fatalf("ledger summary hits=%d uniq=%d err=%v", hits, uniq, err)
	}

	// ApplyBlock must be fail-soft (nil) even without cloud creds
	err = blocker.ApplyBlock(context.Background(), models.DisruptionEvent{
		SourceIP: pub, Reason: "test", Action: models.DisruptActionBlock, DryRun: true,
	}, true)
	if err != nil {
		t.Fatalf("ApplyBlock should fail-soft: %v", err)
	}
}
