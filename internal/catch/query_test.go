package catch

import (
	"strings"
	"testing"
	"time"
)

func TestListDossierExportAndHook(t *testing.T) {
	dir := t.TempDir()
	var hooked string
	l := New(dir).WithHook(func(r Record) { hooked = r.IP })

	_ = l.Record(Record{Source: "honeypot", IP: "198.51.100.9", Service: "http", Path: "/login", Reason: "auth_burn"})
	time.Sleep(20 * time.Millisecond)
	if hooked != "198.51.100.9" {
		t.Fatalf("hook not fired: %q", hooked)
	}

	d, err := l.GetDossier("198.51.100.9")
	if err != nil || d.HitCount != 1 {
		t.Fatalf("dossier: %+v err=%v", d, err)
	}
	list, err := l.ListDossiers(10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %d err=%v", len(list), err)
	}
	md, err := l.ExportMarkdown("198.51.100.9")
	if err != nil || !strings.Contains(md, "198.51.100.9") || !strings.Contains(md, "Hit count") {
		t.Fatalf("export: %v %s", err, md)
	}
	byIP, err := l.ListByIP("198.51.100.9", 5)
	if err != nil || len(byIP) != 1 {
		t.Fatalf("byIP: %d %v", len(byIP), err)
	}
}
