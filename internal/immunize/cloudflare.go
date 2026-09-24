package immunize

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
)

// CloudflareBanProvider blocks IPs via Cloudflare Firewall Access Rules (owned zones).
type CloudflareBanProvider struct {
	APIToken string
	ZoneID   string
	Client   *http.Client
	Log      *slog.Logger
	DryRun   bool
}

func NewCloudflare(apiToken, zoneID string, dryRun bool, log *slog.Logger) *CloudflareBanProvider {
	tok := first(apiToken, os.Getenv("CLOUDFLARE_API_TOKEN"))
	zid := first(zoneID, os.Getenv("CLOUDFLARE_ZONE_ID"))
	return &CloudflareBanProvider{
		APIToken: tok,
		ZoneID:   zid,
		Client:   &http.Client{Timeout: 8 * time.Second},
		Log:      log,
		DryRun:   dryRun,
	}
}

func (cf *CloudflareBanProvider) Enabled() bool {
	return cf != nil && cf.APIToken != "" && cf.ZoneID != ""
}

func (cf *CloudflareBanProvider) BanIP(ctx context.Context, ipAddress, reason string) error {
	if cf == nil {
		return nil
	}
	if net.ParseIP(ipAddress) == nil {
		return fmt.Errorf("invalid ip")
	}
	if isPrivate(ipAddress) {
		return fmt.Errorf("refusing private/local ip")
	}
	if cf.DryRun || !cf.Enabled() {
		if cf.Log != nil {
			cf.Log.Info("cloudflare ban dry-run/skip", "ip", ipAddress, "reason", reason, "configured", cf.Enabled())
		}
		return nil
	}

	url := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/firewall/access_rules/rules", cf.ZoneID)
	payload := map[string]any{
		"mode": "block",
		"configuration": map[string]string{
			"target": "ip",
			"value":  ipAddress,
		},
		"notes": fmt.Sprintf("ATDE Deception | %s | %s", reason, time.Now().UTC().Format(time.RFC3339)),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cf.APIToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := cf.Client.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare HTTP: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var cfResp struct {
		Success bool            `json:"success"`
		Errors  json.RawMessage `json:"errors"`
	}
	_ = json.Unmarshal(respBody, &cfResp)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && cfResp.Success {
		if cf.Log != nil {
			cf.Log.Info("cloudflare banned", "ip", ipAddress)
		}
		return nil
	}
	return fmt.Errorf("cloudflare status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
}

// MultiCloudDispatcher fans out bans to Cloudflare, AWS WAF webhook/SDK, and generic WAF URL.
type MultiCloudDispatcher struct {
	Cloudflare *CloudflareBanProvider
	AWS        AWSBanner
	WAFWebhook string
	Log        *slog.Logger
	DryRun     bool
	hc         *http.Client
}

// AWSBanner is implemented by webhook and/or native WAFv2 providers.
type AWSBanner interface {
	BanIP(ctx context.Context, ipAddress string) error
	Enabled() bool
}

func NewMultiCloud(cf *CloudflareBanProvider, aws AWSBanner, wafWebhook string, dryRun bool, log *slog.Logger) *MultiCloudDispatcher {
	return &MultiCloudDispatcher{
		Cloudflare: cf,
		AWS:        aws,
		WAFWebhook: first(wafWebhook, os.Getenv("AWS_WAF_BLOCK_ENDPOINT"), os.Getenv("WAF_BLOCK_WEBHOOK")),
		Log:        log,
		DryRun:     dryRun,
		hc:         &http.Client{Timeout: 8 * time.Second},
	}
}

func (m *MultiCloudDispatcher) AutoBlockIP(ctx context.Context, ipAddress, reason string) {
	var wg sync.WaitGroup

	if m.Cloudflare != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Cloudflare.BanIP(ctx, ipAddress, reason); err != nil && m.Log != nil {
				m.Log.Error("cloudflare ban failed", "ip", ipAddress, "err", err)
			}
		}()
	}

	if m.AWS != nil && m.AWS.Enabled() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			defer cancel()
			if err := m.AWS.BanIP(cctx, ipAddress); err != nil && m.Log != nil {
				m.Log.Error("aws waf ban failed", "ip", ipAddress, "err", err)
			} else if m.Log != nil {
				m.Log.Info("aws waf banned", "ip", ipAddress)
			}
		}()
	}

	if m.WAFWebhook != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if m.DryRun {
				if m.Log != nil {
					m.Log.Info("waf webhook dry-run", "ip", ipAddress, "url", m.WAFWebhook)
				}
				return
			}
			payload, _ := json.Marshal(map[string]string{
				"action": "BLOCK_IP",
				"ip":     ipAddress,
				"reason": fmt.Sprintf("Deception Engine: %s", reason),
				"ttl":    "86400",
			})
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.WAFWebhook, bytes.NewReader(payload))
			if err != nil {
				return
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := m.hc.Do(req)
			if err != nil {
				if m.Log != nil {
					m.Log.Error("waf webhook failed", "err", err)
				}
				return
			}
			defer resp.Body.Close()
			if m.Log != nil {
				m.Log.Info("waf webhook immunized", "ip", ipAddress, "status", resp.StatusCode)
			}
		}()
	}

	wg.Wait()
}

func first(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func isPrivate(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return true
	}
	return p.IsLoopback() || p.IsPrivate() || p.IsLinkLocalUnicast() ||
		strings.HasPrefix(ip, "192.0.2.") || strings.HasPrefix(ip, "198.51.100.") || strings.HasPrefix(ip, "203.0.113.")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
