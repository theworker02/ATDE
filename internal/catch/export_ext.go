package catch

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// SeedFromJSONL imports records from a JSONL file (e.g. demo-evidence) into the ledger.
func (l *Ledger) SeedFromJSONL(path string) (int, error) {
	if l == nil {
		return 0, fmt.Errorf("catch: nil ledger")
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	n := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return n, fmt.Errorf("seed line %d: %w", n+1, err)
		}
		if r.ID == "" {
			r.ID = fmt.Sprintf("seed_%d", time.Now().UnixNano())
		}
		if err := l.Record(r); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}

// ExportSTIX builds a minimal STIX 2.1 bundle (indicator + observed-data) for one IP.
func (l *Ledger) ExportSTIX(ip string) (string, error) {
	d, err := l.GetDossier(ip)
	if err != nil {
		return "", err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	indID := "indicator--atde-" + sanitize(ip)
	obsID := "observed-data--atde-" + sanitize(ip)
	bundle := map[string]any{
		"type":        "bundle",
		"id":          "bundle--atde-" + sanitize(ip),
		"spec_version": "2.1",
		"objects": []map[string]any{
			{
				"type":        "indicator",
				"spec_version": "2.1",
				"id":          indID,
				"created":     d.FirstSeen.UTC().Format(time.RFC3339),
				"modified":    d.LastSeen.UTC().Format(time.RFC3339),
				"name":        "ATDE catch — " + d.IP,
				"description": d.LastSummary,
				"pattern":     "[ipv4-addr:value = '" + d.IP + "']",
				"pattern_type": "stix",
				"valid_from":  d.FirstSeen.UTC().Format(time.RFC3339),
				"labels":      append([]string{"atde", "honeypot"}, d.Tags...),
				"confidence":  min(100, max(0, d.MaxSeverity)),
			},
			{
				"type":         "observed-data",
				"spec_version": "2.1",
				"id":           obsID,
				"created":      now,
				"modified":     now,
				"first_observed": d.FirstSeen.UTC().Format(time.RFC3339),
				"last_observed":  d.LastSeen.UTC().Format(time.RFC3339),
				"number_observed": d.HitCount,
				"objects": map[string]any{
					"0": map[string]any{"type": "ipv4-addr", "value": d.IP},
				},
				"labels": d.Services,
			},
		},
	}
	raw, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ExportAbuseBundle writes Markdown + STIX for one IP under outDir.
func (l *Ledger) ExportAbuseBundle(ip, outDir string) (mdPath, stixPath string, err error) {
	if outDir == "" {
		outDir = filepath.Join("data", "evidence")
	}
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return "", "", err
	}
	safe := sanitize(StripPort(ip))
	md, err := l.ExportMarkdown(ip)
	if err != nil {
		return "", "", err
	}
	stix, err := l.ExportSTIX(ip)
	if err != nil {
		return "", "", err
	}
	mdPath = filepath.Join(outDir, "atde-"+safe+".md")
	stixPath = filepath.Join(outDir, "atde-"+safe+".stix.json")
	if err := os.WriteFile(mdPath, []byte(md), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(stixPath, []byte(stix), 0o600); err != nil {
		return "", "", err
	}
	return mdPath, stixPath, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
