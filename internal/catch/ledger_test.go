package catch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLedgerEventsAndDossier(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)

	err := l.Record(Record{
		Source:  "honeypot",
		IP:      "203.0.113.50:443",
		Service: "http",
		Path:    "/wp-login.php",
		Reason:  "scanner probe",
		Actions: []string{"recorded", "tarpit"},
	})
	if err != nil {
		t.Fatal(err)
	}
	err = l.Record(Record{
		Source:  "active",
		IP:      "203.0.113.50",
		Reason:  "honeypot_interaction",
		Actions: []string{"local_firewall"},
		Blocked: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	events := filepath.Join(dir, "events.jsonl")
	if _, err := os.Stat(events); err != nil {
		t.Fatalf("events.jsonl missing: %v", err)
	}
	dossier := filepath.Join(dir, "dossier_203.0.113.50.json")
	raw, err := os.ReadFile(dossier)
	if err != nil {
		t.Fatalf("dossier missing: %v", err)
	}
	if !contains(string(raw), `"hit_count": 2`) {
		t.Fatalf("expected hit_count 2 in %s", raw)
	}
	if !contains(string(raw), `"blocked": true`) {
		t.Fatalf("expected blocked true in %s", raw)
	}

	recs, err := l.ListRecent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 events, got %d", len(recs))
	}
	if recs[0].IP != "203.0.113.50" {
		t.Fatalf("port not stripped: %q", recs[0].IP)
	}
	hits, uniq, err := l.Summary()
	if err != nil || hits != 2 || uniq != 1 {
		t.Fatalf("summary=%d/%d err=%v", hits, uniq, err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(func() bool {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
			return false
		})())
}
