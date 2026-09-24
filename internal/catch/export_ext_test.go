package catch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeedExportSTIX(t *testing.T) {
	dir := t.TempDir()
	l := New(dir)
	seed := filepath.Join(dir, "seed.jsonl")
	body := `{"id":"t1","caught_at":"2026-09-24T14:00:00Z","source":"honeypot","ip":"203.0.113.9","service":"mysql-bait","reason":"honeypot_hit","severity":75,"summary":"MySQL bait","blocked":false,"private_ip":false}
{"id":"t2","caught_at":"2026-09-24T14:01:00Z","source":"honeypot","ip":"203.0.113.9","service":"ftp-bait","reason":"honeypot_hit","severity":55,"summary":"FTP bait","blocked":false,"private_ip":false}
`
	if err := os.WriteFile(seed, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := l.SeedFromJSONL(seed)
	if err != nil || n != 2 {
		t.Fatalf("seed n=%d err=%v", n, err)
	}
	stix, err := l.ExportSTIX("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"indicator", "203.0.113.9", "bundle"} {
		if !strings.Contains(stix, p) {
			t.Fatalf("missing %q in stix", p)
		}
	}
	md, stixPath, err := l.ExportAbuseBundle("203.0.113.9", filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(md); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stixPath); err != nil {
		t.Fatal(err)
	}
}
