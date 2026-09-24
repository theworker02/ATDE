package publish_test

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theworker02/blind-botnet/internal/config"
	"github.com/theworker02/blind-botnet/internal/models"
	"github.com/theworker02/blind-botnet/internal/publish"
)

func TestSTIXAndMarkdownEvidence(t *testing.T) {
	dir := t.TempDir()
	p := publish.New(config.PublishConfig{
		Enabled:     true,
		DryRun:      true,
		EvidenceDir: dir,
	}, nil, slog.Default())

	evt := models.PublishEvent{
		ID:           "evt_pub_test",
		Timestamp:    time.Now().UTC(),
		ThreatType:   "phishing_credential_harvester",
		TargetDomain: "login-chase-security-update.com",
		AttackerIP:   "192.0.2.14",
		IOCs:         []string{"login-chase-security-update.com", "192.0.2.14"},
		Summary:      "test advisory",
		DryRun:       true,
	}
	md := p.MarkdownForTest(evt)
	stix := p.STIXForTest(evt)
	if len(md) < 40 {
		t.Fatal("markdown too short")
	}
	raw, err := json.Marshal(stix)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "stix.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle["type"] != "bundle" {
		t.Fatalf("expected stix bundle, got %v", bundle["type"])
	}
}
