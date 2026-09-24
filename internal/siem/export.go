package siem

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/theworker02/ATDE/v2/internal/catch"
)

// ECSDocument is a minimal Elastic Common Schema event for SIEM ingest.
type ECSDocument struct {
	Timestamp  string         `json:"@timestamp"`
	Event      map[string]any `json:"event"`
	Source     map[string]any `json:"source"`
	Threat     map[string]any `json:"threat,omitempty"`
	Observer   map[string]any `json:"observer"`
	ATDE       map[string]any `json:"atde"`
	Message    string         `json:"message"`
}

// ToECS maps a catch record to ECS JSON.
func ToECS(r catch.Record) ECSDocument {
	techs := make([]map[string]string, 0, len(r.Techniques))
	for _, t := range r.Techniques {
		techs = append(techs, map[string]string{"id": t})
	}
	return ECSDocument{
		Timestamp: r.CaughtAt.UTC().Format(time.RFC3339Nano),
		Event: map[string]any{
			"kind":     "alert",
			"category": []string{"intrusion_detection", "network"},
			"type":     []string{"denied", "info"},
			"severity": r.Severity,
			"action":   strings.Join(r.Actions, ","),
			"dataset":  "atde.catch",
			"module":   "atde",
		},
		Source: map[string]any{
			"ip": r.IP,
		},
		Threat: map[string]any{
			"technique": techs,
			"software":  map[string]any{"name": r.Tool},
		},
		Observer: map[string]any{
			"product":  "ATDE",
			"vendor":   "ATDE",
			"type":     "honeypot",
			"version":  "2.0",
		},
		ATDE: map[string]any{
			"service":     r.Service,
			"path":        r.Path,
			"tags":        r.Tags,
			"policy_tier": r.PolicyTier,
			"campaign_id": r.CampaignID,
			"summary":     r.Summary,
		},
		Message: fmt.Sprintf("ATDE catch %s sev=%d %s", r.IP, r.Severity, r.Summary),
	}
}

// ToECSJSONL encodes many records as ECS JSONL.
func ToECSJSONL(recs []catch.Record) (string, error) {
	var b strings.Builder
	for _, r := range recs {
		raw, err := json.Marshal(ToECS(r))
		if err != nil {
			return "", err
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// ToCEF encodes a single ArcSight CEF line.
func ToCEF(r catch.Record) string {
	// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
	name := r.Summary
	if name == "" {
		name = r.Reason
	}
	name = strings.ReplaceAll(name, "|", "/")
	ext := fmt.Sprintf("src=%s spt=0 cs1Label=service cs1=%s cs2Label=tool cs2=%s cs3Label=tags cs3=%s cs4Label=techniques cs4=%s msg=%s",
		r.IP, cefEsc(r.Service), cefEsc(r.Tool), cefEsc(strings.Join(r.Tags, ",")),
		cefEsc(strings.Join(r.Techniques, ",")), cefEsc(r.Summary))
	return fmt.Sprintf("CEF:0|ATDE|ATDE Catch|2.0|honeypot_hit|%s|%d|%s", name, sevCEF(r.Severity), ext)
}

func sevCEF(s int) int {
	// map 1-100 → 0-10
	n := s / 10
	if n > 10 {
		return 10
	}
	if n < 0 {
		return 0
	}
	return n
}

func cefEsc(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "=", "\\=")
	s = strings.ReplaceAll(s, "\n", " ")
	return s
}

// ToMISP builds a minimal MISP Event JSON for TIP ingest.
func ToMISP(d *catch.Dossier, recs []catch.Record) map[string]any {
	attrs := []map[string]any{
		{
			"type":     "ip-src",
			"value":    d.IP,
			"category": "Network activity",
			"to_ids":   true,
			"comment":  d.LastSummary,
		},
	}
	for _, t := range d.Techniques {
		attrs = append(attrs, map[string]any{
			"type": "comment", "category": "Other", "value": "MITRE " + t, "to_ids": false,
		})
	}
	for _, t := range d.Tags {
		attrs = append(attrs, map[string]any{
			"type": "text", "category": "Other", "value": "tag:" + t, "to_ids": false,
		})
	}
	_ = recs
	return map[string]any{
		"Event": map[string]any{
			"info":            fmt.Sprintf("ATDE catch %s — %s", d.IP, d.LastSummary),
			"threat_level_id": mispThreat(d.MaxSeverity),
			"analysis":        "1",
			"distribution":    "0",
			"Attribute":       attrs,
			"Tag": []map[string]string{
				{"name": "atde:catch"},
				{"name": "tlp:amber"},
			},
		},
	}
}

func mispThreat(sev int) string {
	switch {
	case sev >= 80:
		return "1" // high
	case sev >= 50:
		return "2" // medium
	default:
		return "3" // low
	}
}
