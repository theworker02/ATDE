package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/theworker02/blind-botnet/v2/internal/config"
	"github.com/theworker02/blind-botnet/v2/internal/immunize"
	"github.com/theworker02/blind-botnet/v2/internal/models"
)

// Result describes what EnforceContainment actually did.
type Result struct {
	IP           string   `json:"ip"`
	LocalOK      bool     `json:"local_ok"`
	LocalSkipped bool     `json:"local_skipped,omitempty"` // private IP or disabled
	LocalErr     string   `json:"local_err,omitempty"`
	CloudTried   []string `json:"cloud_tried,omitempty"`
	CloudErrors  []string `json:"cloud_errors,omitempty"`
}

// Blocker pushes block rules: local-first (mandatory), cloud best-effort.
type Blocker struct {
	cfg   config.EdgeConfig
	log   *slog.Logger
	hc    *http.Client
	aws   *immunize.AWSWAFBanProvider
	cf    *immunize.CloudflareBanProvider
	local *LocalFirewall
}

func New(cfg config.EdgeConfig, log *slog.Logger) *Blocker {
	aws := immunize.NewAWSWAF(context.Background(), cfg.AWSRegion, cfg.AWSIPSetID, cfg.AWSIPSetName, cfg.AWSCloudFront, cfg.DryRun, log)
	cf := immunize.NewCloudflare(cfg.CloudflareToken, cfg.CloudflareZoneID, cfg.DryRun, log)
	lf := NewLocalFirewall(cfg.LocalFirewall, cfg.DryRun, log)
	b := &Blocker{
		cfg:   cfg,
		log:   log,
		hc:    &http.Client{Timeout: 30 * time.Second},
		aws:   aws,
		cf:    cf,
		local: lf,
	}
	// Best-effort warm-up of ipset (non-fatal).
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = lf.EnsureReady(ctx)
	}()
	return b
}

// ApplyBlock is the NATS disrupt consumer entrypoint. Cloud failures never
// abort the pipeline; only missing/invalid IP returns an error.
func (b *Blocker) ApplyBlock(ctx context.Context, evt models.DisruptionEvent, dryRun bool) error {
	ip := strings.TrimSpace(evt.SourceIP)
	if ip == "" {
		return fmt.Errorf("missing source_ip")
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid ip: %s", ip)
	}

	dry := dryRun || evt.DryRun || b.cfg.DryRun
	score := 0.9 // disrupt block events are already gated upstream
	res := b.EnforceContainment(ctx, ip, evt.Reason, score, dry)
	b.log.Info("containment result",
		"ip", res.IP,
		"local_ok", res.LocalOK,
		"local_skipped", res.LocalSkipped,
		"cloud_tried", res.CloudTried,
		"cloud_errors", len(res.CloudErrors),
	)
	return nil // fail-soft: local path logged; cloud best-effort
}

// EnforceContainment runs local OS block first (guaranteed attempt), then
// fires cloud integrations asynchronously. Cloud errors are logged, never fatal.
func (b *Blocker) EnforceContainment(ctx context.Context, ip, reason string, score float64, dry bool) Result {
	res := Result{IP: ip}
	if score < 0.8 {
		b.log.Debug("containment skipped: below confidence", "ip", ip, "score", score)
		res.LocalSkipped = true
		return res
	}
	if isPrivateOrLocal(ip) {
		b.log.Info("containment: private/local IP recorded only (no OS block)", "ip", ip)
		res.LocalSkipped = true
		return res
	}

	// 1. Local OS block — mandatory when enabled
	if b.local != nil && b.cfg.LocalFirewall {
		b.local.DryRun = dry
		if err := b.local.BlockIP(ctx, ip, reason); err != nil {
			res.LocalErr = err.Error()
			b.log.Warn("local firewall block failed", "ip", ip, "err", err)
		} else {
			res.LocalOK = true
		}
	} else {
		res.LocalSkipped = true
		b.log.Info("local firewall skipped", "ip", ip, "enabled", b.cfg.LocalFirewall, "dry_run", dry)
	}

	if dry {
		return res
	}

	// 2. Cloud integrations — best-effort, non-blocking
	var wg sync.WaitGroup
	var mu sync.Mutex
	addCloud := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock()
			res.CloudTried = append(res.CloudTried, name)
			mu.Unlock()
			if err := fn(); err != nil {
				mu.Lock()
				res.CloudErrors = append(res.CloudErrors, name+": "+err.Error())
				mu.Unlock()
				b.log.Warn("cloud ban failed (continuing)", "provider", name, "ip", ip, "err", err)
			}
		}()
	}

	if b.cf != nil && b.cf.Enabled() {
		addCloud("cloudflare", func() error {
			b.cf.DryRun = false
			return b.cf.BanIP(ctx, ip, reason)
		})
	}
	if b.aws != nil && b.aws.Enabled() {
		addCloud("aws_waf", func() error {
			b.aws.DryRun = false
			return b.aws.BanIP(ctx, ip)
		})
	}
	endpoint := firstNonEmpty(b.cfg.AWSWAFEndpoint, os.Getenv("AWS_WAF_BLOCK_ENDPOINT"), os.Getenv("WAF_BLOCK_WEBHOOK"))
	if endpoint != "" && (b.aws == nil || !b.aws.Enabled()) {
		addCloud("waf_webhook", func() error {
			return b.postWAFWebhook(ctx, endpoint, ip, reason)
		})
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	case <-time.After(12 * time.Second):
		b.log.Warn("cloud containment still running; returning (local already applied)", "ip", ip)
	}
	return res
}

func (b *Blocker) postWAFWebhook(ctx context.Context, endpoint, ip, reason string) error {
	payload, _ := json.Marshal(map[string]any{"action": "BLOCK_IP", "ip": ip, "reason": reason, "source": "atde", "ttl": "86400"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		b.log.Info("edge blocked via waf webhook", "ip", ip)
		return nil
	}
	return fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(body), 200))
}

func isPrivateOrLocal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() || parsed.IsPrivate() {
		return true
	}
	return strings.HasPrefix(ip, "192.0.2.") || strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "203.0.113.")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
