package siem

import (
	"strings"
	"testing"
	"time"

	"github.com/theworker02/blind-botnet/internal/catch"
)

func TestExports(t *testing.T) {
	r := catch.Record{
		IP: "203.0.113.9", CaughtAt: time.Now().UTC(), Severity: 80,
		Service: "http", Tool: "nuclei", Tags: []string{"vuln-bait"},
		Techniques: []string{"T1595"}, Summary: "scan", Reason: "honeypot_hit",
		Actions: []string{"recorded"},
	}
	ecs := ToECS(r)
	if ecs.Source["ip"] != "203.0.113.9" {
		t.Fatal(ecs)
	}
	cef := ToCEF(r)
	if !strings.Contains(cef, "CEF:0|ATDE") {
		t.Fatal(cef)
	}
	d := &catch.Dossier{IP: r.IP, MaxSeverity: 80, LastSummary: "scan", Techniques: r.Techniques, Tags: r.Tags}
	m := ToMISP(d, []catch.Record{r})
	if m["Event"] == nil {
		t.Fatal("misp")
	}
}
