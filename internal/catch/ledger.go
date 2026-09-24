package catch

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Record is one attacker interaction worth keeping for response / LE handoff.
type Record struct {
	ID          string            `json:"id"`
	CaughtAt    time.Time         `json:"caught_at"`
	Source      string            `json:"source"` // honeypot|deception|ct|active|enrich|policy
	IP          string            `json:"ip"`
	Service     string            `json:"service,omitempty"`
	Path        string            `json:"path,omitempty"`
	Method      string            `json:"method,omitempty"`
	UserAgent   string            `json:"user_agent,omitempty"`
	Reason      string            `json:"reason"`
	Actions     []string          `json:"actions,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Tool        string            `json:"tool,omitempty"`
	Severity    int               `json:"severity,omitempty"`
	Summary     string            `json:"summary,omitempty"`
	Techniques  []string          `json:"techniques,omitempty"` // MITRE ATT&CK
	CampaignID  string            `json:"campaign_id,omitempty"`
	PolicyTier string            `json:"policy_tier,omitempty"`
	Blocked     bool              `json:"blocked"`
	PrivateIP   bool              `json:"private_ip"`
}

// Dossier is the rolling per-IP summary used for abuse handoff.
type Dossier struct {
	IP           string            `json:"ip"`
	FirstSeen    time.Time         `json:"first_seen"`
	LastSeen     time.Time         `json:"last_seen"`
	HitCount     int               `json:"hit_count"`
	Blocked      bool              `json:"blocked"`
	PrivateIP    bool              `json:"private_ip"`
	MaxSeverity  int               `json:"max_severity,omitempty"`
	Tools        []string          `json:"tools,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Sources      []string          `json:"sources,omitempty"`
	Services     []string          `json:"services,omitempty"`
	Paths        []string          `json:"paths,omitempty"`
	Reasons      []string          `json:"reasons,omitempty"`
	Actions      []string          `json:"actions,omitempty"`
	UserAgents   []string          `json:"user_agents,omitempty"`
	LastSummary  string            `json:"last_summary,omitempty"`
	LastRecordID string            `json:"last_record_id,omitempty"`
	Techniques   []string          `json:"techniques,omitempty"`
	CampaignIDs  []string          `json:"campaign_ids,omitempty"`
	PolicyTier   string            `json:"policy_tier,omitempty"`
	Meta         map[string]string `json:"meta,omitempty"`
}

// Ledger appends events.jsonl and maintains dossier_<IP>.json under dir.
type Ledger struct {
	Dir  string
	mu   sync.Mutex
	hook OnRecord
}

func New(dir string) *Ledger {
	if strings.TrimSpace(dir) == "" {
		dir = "./data/caught"
	}
	return &Ledger{Dir: dir}
}

// Record writes an append-only audit event and updates the per-IP dossier.
func (l *Ledger) Record(r Record) error {
	if l == nil {
		return nil
	}
	if r.CaughtAt.IsZero() {
		r.CaughtAt = time.Now().UTC()
	}
	r.IP = StripPort(r.IP)
	if r.IP == "" {
		return fmt.Errorf("catch: missing ip")
	}
	if !strings.HasPrefix(r.IP, "domain:") {
		r.PrivateIP = IsPrivateOrLocal(r.IP)
	}
	if r.ID == "" {
		r.ID = "catch_" + r.CaughtAt.Format("20060102150405.000000") + "_" + sanitize(r.IP)
	}
	if len(r.Actions) == 0 {
		r.Actions = []string{"recorded"}
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(l.Dir, 0o750); err != nil {
		return err
	}

	// Append-only audit trail (primary).
	eventsPath := filepath.Join(l.Dir, "events.jsonl")
	if err := appendJSONL(eventsPath, r); err != nil {
		return err
	}
	// Daily shard for operators who rotate by date.
	dayPath := filepath.Join(l.Dir, "caught-"+r.CaughtAt.UTC().Format("2006-01-02")+".jsonl")
	_ = appendJSONL(dayPath, r)

	if err := l.upsertDossier(r); err != nil {
		return err
	}
	if l.hook != nil {
		rr := r
		go l.hook(rr)
	}
	return nil
}

func appendJSONL(path string, r Record) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(r)
}

func (l *Ledger) upsertDossier(r Record) error {
	path := filepath.Join(l.Dir, "dossier_"+sanitize(r.IP)+".json")
	var d Dossier
	if raw, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(raw, &d)
	}
	if d.IP == "" {
		d.IP = r.IP
		d.FirstSeen = r.CaughtAt
		d.Meta = map[string]string{}
	}
	d.LastSeen = r.CaughtAt
	d.HitCount++
	d.Blocked = d.Blocked || r.Blocked
	d.PrivateIP = r.PrivateIP
	d.LastRecordID = r.ID
	if r.Summary != "" {
		d.LastSummary = r.Summary
	}
	if r.Severity > d.MaxSeverity {
		d.MaxSeverity = r.Severity
	}
	d.Tools = appendUnique(d.Tools, r.Tool)
	for _, t := range r.Tags {
		d.Tags = appendUnique(d.Tags, t)
	}
	for _, t := range r.Techniques {
		d.Techniques = appendUnique(d.Techniques, t)
	}
	if r.CampaignID != "" {
		d.CampaignIDs = appendUnique(d.CampaignIDs, r.CampaignID)
	}
	if r.PolicyTier != "" {
		d.PolicyTier = r.PolicyTier
	}
	d.Sources = appendUnique(d.Sources, r.Source)
	d.Services = appendUnique(d.Services, r.Service)
	d.Paths = appendUnique(d.Paths, r.Path)
	d.Reasons = appendUnique(d.Reasons, r.Reason)
	d.UserAgents = appendUnique(d.UserAgents, r.UserAgent)
	for _, a := range r.Actions {
		d.Actions = appendUnique(d.Actions, a)
	}
	for k, v := range r.Meta {
		if d.Meta == nil {
			d.Meta = map[string]string{}
		}
		d.Meta[k] = v
	}
	// Cap growth for abuse-package readability.
	d.Paths = capSlice(d.Paths, 50)
	d.Reasons = capSlice(d.Reasons, 50)
	d.UserAgents = capSlice(d.UserAgents, 20)
	d.Tags = capSlice(d.Tags, 40)
	d.Tools = capSlice(d.Tools, 20)
	d.Techniques = capSlice(d.Techniques, 30)
	d.CampaignIDs = capSlice(d.CampaignIDs, 10)

	raw, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

// ListRecent returns up to limit records from events.jsonl (fallback: daily shards).
func (l *Ledger) ListRecent(limit int) ([]Record, error) {
	if l == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 50
	}
	path := filepath.Join(l.Dir, "events.jsonl")
	recs, err := readJSONL(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if len(recs) == 0 {
		now := time.Now().UTC()
		for _, day := range []string{now.Format("2006-01-02"), now.Add(-24 * time.Hour).Format("2006-01-02")} {
			dayRecs, dayErr := readJSONL(filepath.Join(l.Dir, "caught-"+day+".jsonl"))
			if dayErr != nil {
				continue
			}
			recs = append(recs, dayRecs...)
		}
	}
	if len(recs) > limit {
		recs = recs[len(recs)-limit:]
	}
	return recs, nil
}

// Summary counts unique IPs and total hits from the audit log.
func (l *Ledger) Summary() (hits int, uniqueIPs int, err error) {
	recs, err := l.ListRecent(10_000)
	if err != nil {
		return 0, 0, err
	}
	seen := map[string]struct{}{}
	for _, r := range recs {
		hits++
		seen[r.IP] = struct{}{}
	}
	return hits, len(seen), nil
}

func readJSONL(path string) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

func StripPort(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return strings.Trim(addr, "[]")
}

func IsPrivateOrLocal(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return true
	}
	return p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() ||
		strings.HasPrefix(ip, "192.0.2.") || strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "203.0.113.")
}

func Sanitize(s string) string {
	return sanitize(s)
}

func sanitize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == ':' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 80 {
		out = out[:80]
	}
	return out
}

func appendUnique(slice []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return slice
	}
	for _, s := range slice {
		if s == v {
			return slice
		}
	}
	return append(slice, v)
}

func capSlice(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[len(in)-n:]
}
