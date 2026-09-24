package campaign

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/theworker02/blind-botnet/internal/catch"
)

// Campaign groups related attacker IPs by shared tradecraft.
type Campaign struct {
	ID         string    `json:"id"`
	Label      string    `json:"label"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	IPs        []string  `json:"ips"`
	Tools      []string  `json:"tools"`
	Tags       []string  `json:"tags"`
	Services   []string  `json:"services"`
	Techniques []string  `json:"techniques,omitempty"`
	HitCount   int       `json:"hit_count"`
	MaxSev     int       `json:"max_severity"`
	Summary    string    `json:"summary"`
}

// Correlate builds campaigns from recent ledger events (defensive intel only).
func Correlate(recs []catch.Record, window time.Duration) []Campaign {
	if window <= 0 {
		window = 24 * time.Hour
	}
	cutoff := time.Now().UTC().Add(-window)
	type bucket struct {
		key  string
		recs []catch.Record
	}
	groups := map[string]*bucket{}
	for _, r := range recs {
		if r.CaughtAt.Before(cutoff) {
			continue
		}
		key := fingerprintKey(r)
		if key == "" {
			continue
		}
		b, ok := groups[key]
		if !ok {
			b = &bucket{key: key}
			groups[key] = b
		}
		b.recs = append(b.recs, r)
	}
	var out []Campaign
	for _, b := range groups {
		if len(b.recs) < 2 && uniqueIPs(b.recs) < 1 {
			continue
		}
		c := buildCampaign(b.key, b.recs)
		// Keep single-IP campaigns only if multi-hit or high severity.
		if len(c.IPs) == 1 && c.HitCount < 3 && c.MaxSev < 60 {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MaxSev == out[j].MaxSev {
			return out[i].HitCount > out[j].HitCount
		}
		return out[i].MaxSev > out[j].MaxSev
	})
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func fingerprintKey(r catch.Record) string {
	parts := []string{r.Tool}
	tags := append([]string{}, r.Tags...)
	sort.Strings(tags)
	if len(tags) > 4 {
		tags = tags[:4]
	}
	parts = append(parts, strings.Join(tags, ","))
	svc := r.Service
	if svc == "" {
		svc = "unknown"
	}
	parts = append(parts, svcFamily(svc))
	raw := strings.Join(parts, "|")
	if raw == "||unknown" || strings.Trim(raw, "|") == "" {
		return ""
	}
	sum := sha1.Sum([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

func svcFamily(s string) string {
	s = strings.ToLower(s)
	switch {
	case strings.Contains(s, "ssh"):
		return "ssh"
	case strings.Contains(s, "redis"):
		return "redis"
	case strings.Contains(s, "mysql"):
		return "mysql"
	case strings.Contains(s, "ftp"):
		return "ftp"
	case strings.Contains(s, "telnet"):
		return "telnet"
	case strings.Contains(s, "smtp"):
		return "smtp"
	case strings.Contains(s, "mongo"):
		return "mongo"
	case strings.Contains(s, "elastic") || strings.Contains(s, "es"):
		return "elasticsearch"
	case strings.Contains(s, "http") || strings.Contains(s, "login") || strings.Contains(s, "api"):
		return "http"
	default:
		return s
	}
}

func buildCampaign(key string, recs []catch.Record) Campaign {
	c := Campaign{ID: "camp_" + key}
	ips := map[string]struct{}{}
	tools := map[string]struct{}{}
	tags := map[string]struct{}{}
	svcs := map[string]struct{}{}
	techs := map[string]struct{}{}
	for _, r := range recs {
		c.HitCount++
		ips[r.IP] = struct{}{}
		if r.Tool != "" {
			tools[r.Tool] = struct{}{}
		}
		for _, t := range r.Tags {
			tags[t] = struct{}{}
		}
		for _, t := range r.Techniques {
			techs[t] = struct{}{}
		}
		if r.Service != "" {
			svcs[r.Service] = struct{}{}
		}
		if c.FirstSeen.IsZero() || r.CaughtAt.Before(c.FirstSeen) {
			c.FirstSeen = r.CaughtAt
		}
		if r.CaughtAt.After(c.LastSeen) {
			c.LastSeen = r.CaughtAt
		}
		if r.Severity > c.MaxSev {
			c.MaxSev = r.Severity
		}
	}
	c.IPs = keys(ips)
	c.Tools = keys(tools)
	c.Tags = keys(tags)
	c.Services = keys(svcs)
	c.Techniques = keys(techs)
	c.Label = labelFor(c)
	c.Summary = fmt.Sprintf("%d hits across %d IPs · max sev %d · tools %s",
		c.HitCount, len(c.IPs), c.MaxSev, strings.Join(c.Tools, ","))
	return c
}

func labelFor(c Campaign) string {
	if len(c.Tools) > 0 && c.Tools[0] != "unknown" {
		return c.Tools[0] + "-wave"
	}
	if len(c.Tags) > 0 {
		return c.Tags[0] + "-cluster"
	}
	return "mixed-scan"
}

func uniqueIPs(recs []catch.Record) int {
	m := map[string]struct{}{}
	for _, r := range recs {
		m[r.IP] = struct{}{}
	}
	return len(m)
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k == "" {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
