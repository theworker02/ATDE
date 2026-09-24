package policy

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/theworker02/ATDE/v2/internal/catch"
	"github.com/theworker02/ATDE/v2/internal/disrupt/edge"
)

// Tier is a graduated defensive response on infrastructure you own.
type Tier string

const (
	TierObserve   Tier = "observe"    // record only
	TierTarpit    Tier = "tarpit"     // slow decoy responses
	TierLocalBan  Tier = "local_ban"  // OS firewall
	TierCloud     Tier = "cloud"      // CF/AWS best-effort
	TierAbusePack Tier = "abuse_pack" // generate evidence package
)

// Decision is what the policy engine chose for one IP after a hit.
type Decision struct {
	IP         string    `json:"ip"`
	Tier       Tier      `json:"tier"`
	Severity   int       `json:"severity"`
	HitCount   int       `json:"hit_count"`
	Reason     string    `json:"reason"`
	Actions    []string  `json:"actions"`
	DecidedAt  time.Time `json:"decided_at"`
	CampaignID string    `json:"campaign_id,omitempty"`
}

// Config tunes thresholds (all defensive / owned-edge).
type Config struct {
	TarpitSeverity  int // default 35
	LocalBanSev     int // default 55
	LocalBanHits    int // default 2
	CloudSev        int // default 75
	CloudHits       int // default 3
	AbusePackSev    int // default 70
	AutoAbuseExport bool
}

func DefaultConfig() Config {
	return Config{
		TarpitSeverity:  35,
		LocalBanSev:     55,
		LocalBanHits:    2,
		CloudSev:        75,
		CloudHits:       3,
		AbusePackSev:    70,
		AutoAbuseExport: true,
	}
}

// Engine applies graduated disruption on owned edge only.
type Engine struct {
	cfg     Config
	log     *slog.Logger
	blocker *edge.Blocker
	ledger  *catch.Ledger
	mu      sync.Mutex
	hits    map[string]int
	last    map[string]Decision
}

func New(cfg Config, log *slog.Logger) *Engine {
	if cfg.LocalBanHits == 0 {
		cfg = DefaultConfig()
	}
	return &Engine{
		cfg:  cfg,
		log:  log,
		hits: map[string]int{},
		last: map[string]Decision{},
	}
}

func (e *Engine) WithBlocker(b *edge.Blocker) *Engine {
	e.blocker = b
	return e
}

func (e *Engine) WithLedger(l *catch.Ledger) *Engine {
	e.ledger = l
	return e
}

// Evaluate records a hit and returns the tier without side effects beyond counters.
func (e *Engine) Evaluate(ip string, severity int, reason string) Decision {
	e.mu.Lock()
	e.hits[ip]++
	n := e.hits[ip]
	e.mu.Unlock()

	d := Decision{
		IP:        ip,
		Severity:  severity,
		HitCount:  n,
		Reason:    reason,
		DecidedAt: time.Now().UTC(),
		Tier:      TierObserve,
		Actions:   []string{"record"},
	}

	switch {
	case severity >= e.cfg.CloudSev && n >= e.cfg.CloudHits:
		d.Tier = TierCloud
		d.Actions = append(d.Actions, "local_ban", "cloud_escalate", "abuse_pack")
	case severity >= e.cfg.LocalBanSev && n >= e.cfg.LocalBanHits:
		d.Tier = TierLocalBan
		d.Actions = append(d.Actions, "local_ban")
		if severity >= e.cfg.AbusePackSev {
			d.Actions = append(d.Actions, "abuse_pack")
		}
	case severity >= e.cfg.TarpitSeverity:
		d.Tier = TierTarpit
		d.Actions = append(d.Actions, "tarpit")
	default:
		d.Tier = TierObserve
	}

	e.mu.Lock()
	e.last[ip] = d
	e.mu.Unlock()
	return d
}

// Enforce runs owned-edge actions for a decision (never attacks third parties).
func (e *Engine) Enforce(ctx context.Context, d Decision) Decision {
	if e == nil {
		return d
	}
	for _, a := range d.Actions {
		switch a {
		case "local_ban", "cloud_escalate":
			if e.blocker == nil {
				continue
			}
			score := 0.9
			if d.Tier == TierCloud {
				score = 0.98
			}
			res := e.blocker.EnforceContainment(ctx, d.IP, "policy:"+string(d.Tier)+":"+d.Reason, score, false)
			if res.LocalOK && e.ledger != nil {
				_ = e.ledger.Record(catch.Record{
					ID:       fmt.Sprintf("catch_policy_%s_%d", sanitize(d.IP), time.Now().UnixNano()),
					CaughtAt: time.Now().UTC(),
					Source:   "policy",
					IP:       d.IP,
					Reason:   "policy_" + string(d.Tier),
					Actions:  []string{string(d.Tier)},
					Severity: d.Severity,
					Summary:  "Policy engine applied " + string(d.Tier),
					Blocked:  true,
					Tags:     []string{"policy", string(d.Tier)},
				})
			}
			if e.log != nil {
				e.log.Info("policy enforce", "ip", d.IP, "tier", d.Tier, "local_ok", res.LocalOK, "cloud", res.CloudTried)
			}
		case "abuse_pack":
			if !e.cfg.AutoAbuseExport || e.ledger == nil {
				continue
			}
			_, _, err := e.ledger.ExportAbuseBundle(d.IP, "")
			if err != nil && e.log != nil {
				e.log.Debug("abuse pack skipped", "ip", d.IP, "err", err)
			}
		}
	}
	return d
}

// Apply is Evaluate + Enforce.
func (e *Engine) Apply(ctx context.Context, ip string, severity int, reason string) Decision {
	d := e.Evaluate(ip, severity, reason)
	if d.Tier == TierObserve || d.Tier == TierTarpit {
		// tarpit is applied at request time by honeypot; observe is record-only
		return d
	}
	return e.Enforce(ctx, d)
}

func (e *Engine) Last(ip string) (Decision, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	d, ok := e.last[ip]
	return d, ok
}

func (e *Engine) Snapshot() []Decision {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Decision, 0, len(e.last))
	for _, d := range e.last {
		out = append(out, d)
	}
	return out
}

func sanitize(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' {
			b = append(b, c)
		} else {
			b = append(b, '_')
		}
	}
	return string(b)
}
