package campaign

import (
	"testing"
	"time"

	"github.com/theworker02/ATDE/v2/internal/catch"
)

func TestCorrelate(t *testing.T) {
	now := time.Now().UTC()
	recs := []catch.Record{
		{IP: "203.0.113.1", Tool: "nuclei", Tags: []string{"vuln-bait"}, Service: "http", Severity: 70, CaughtAt: now, Techniques: []string{"T1595"}},
		{IP: "203.0.113.2", Tool: "nuclei", Tags: []string{"vuln-bait"}, Service: "http-vuln-bait", Severity: 65, CaughtAt: now.Add(-time.Minute)},
		{IP: "203.0.113.3", Tool: "nuclei", Tags: []string{"vuln-bait"}, Service: "http", Severity: 80, CaughtAt: now.Add(-2 * time.Minute)},
	}
	camps := Correlate(recs, time.Hour)
	if len(camps) == 0 {
		t.Fatal("expected campaign")
	}
	if len(camps[0].IPs) != 3 {
		t.Fatalf("ips=%v", camps[0].IPs)
	}
}
