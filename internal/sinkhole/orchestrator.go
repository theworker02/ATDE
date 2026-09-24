package sinkhole

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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/theworker02/blind-botnet/v2/internal/config"
	"github.com/theworker02/blind-botnet/v2/internal/models"
	"github.com/theworker02/blind-botnet/v2/internal/natsbus"
)

// Orchestrator blinds botnets via owned DNS rewrites and a local sinkhole listener.
// P2P DHT "poisoning" is simulation/evidence-only — no live injection into third-party networks.
type Orchestrator struct {
	cfg    config.SinkholeConfig
	bus    *natsbus.Bus
	log    *slog.Logger
	hc     *http.Client
	mu     sync.Mutex
	hits   map[string]int // infected host IP -> hit count
	rules  map[string]string // domain -> sinkhole IP
}

func New(cfg config.SinkholeConfig, bus *natsbus.Bus, log *slog.Logger) *Orchestrator {
	return &Orchestrator{
		cfg:  cfg,
		bus:  bus,
		log:  log,
		hc:   &http.Client{Timeout: 8 * time.Second},
		hits: map[string]int{},
		rules: map[string]string{},
	}
}

func (o *Orchestrator) Run(ctx context.Context) error {
	if !o.cfg.Enabled {
		o.log.Info("sinkhole engine disabled")
		<-ctx.Done()
		return ctx.Err()
	}

	go o.serveListener(ctx)

	return o.bus.Consume(ctx, models.SubjectSinkhole, "SINKHOLE_DISPATCHER", "sinkhole_workers", o.handle)
}

func (o *Orchestrator) handle(data []byte) error {
	var evt models.SinkholeEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return fmt.Errorf("unmarshal sinkhole: %w", err)
	}
	sinkIP := evt.SinkholeIP
	if sinkIP == "" {
		sinkIP = o.cfg.SinkholeIP
	}
	if sinkIP == "" {
		sinkIP = "127.0.0.1"
	}
	dry := evt.DryRun || o.cfg.DryRun

	o.log.Info("sinkhole job",
		"id", evt.ID,
		"botnet", evt.BotnetName,
		"protocol", evt.Protocol,
		"domains", len(evt.C2Domains),
		"dry_run", dry,
	)

	for _, domain := range evt.C2Domains {
		domain = strings.TrimSpace(strings.ToLower(domain))
		if domain == "" || domain == "honeypot-capture" {
			continue
		}
		if err := o.RedirectC2Domain(domain, sinkIP, dry); err != nil {
			o.log.Error("redirect failed", "domain", domain, "err", err)
		}
	}

	proto := strings.ToLower(evt.Protocol)
	if proto == "p2p_dht" || proto == "p2p" {
		o.SimulateP2PPeerPoison(evt.BotnetName, evt.C2IPs, sinkIP)
	}

	_ = o.persistRules()
	return nil
}

// RedirectC2Domain rewrites resolution for a C2 domain to the sinkhole IP on owned resolvers.
func (o *Orchestrator) RedirectC2Domain(c2Domain, sinkholeIP string, dry bool) error {
	o.log.Info("botnet blinding redirect", "domain", c2Domain, "sinkhole", sinkholeIP, "dry_run", dry)
	o.mu.Lock()
	o.rules[c2Domain] = sinkholeIP
	o.mu.Unlock()

	if dry {
		o.log.Info("sinkhole local sim", "hosts_override", c2Domain+" -> "+sinkholeIP)
		return o.appendHostsOverride(c2Domain, sinkholeIP, true)
	}

	api := firstNonEmpty(o.cfg.CoreDNSAdminURL, os.Getenv("COREDNS_REWRITE_API"))
	if api != "" {
		if err := o.postCoreDNS(api, c2Domain, sinkholeIP); err != nil {
			return err
		}
	} else {
		o.log.Info("no CoreDNS API; writing local override file")
		if err := o.appendHostsOverride(c2Domain, sinkholeIP, false); err != nil {
			return err
		}
	}

	if cf := firstNonEmpty(o.cfg.CloudflareGatewayURL, os.Getenv("CF_GATEWAY_REWRITE_URL")); cf != "" {
		if err := o.postJSON(cf, map[string]any{
			"domain": c2Domain, "rewrite_to": sinkholeIP, "action": "sinkhole_override",
		}); err != nil {
			o.log.Warn("cloudflare gateway rewrite failed", "err", err)
		}
	}
	o.log.Info("blinded", "domain", c2Domain, "sinkhole", sinkholeIP)
	return nil
}

func (o *Orchestrator) postCoreDNS(api, domain, sinkIP string) error {
	payload := map[string]string{
		"domain":     domain,
		"rewrite_to": sinkIP,
		"action":     "sinkhole_override",
		"applied_at": time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)
	url := strings.TrimRight(api, "/") + "/v1/rules/rewrite"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.hc.Do(req)
	if err != nil {
		return fmt.Errorf("dns rewrite controller: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	return fmt.Errorf("DNS API status %d: %s", resp.StatusCode, string(b))
}

func (o *Orchestrator) postJSON(endpoint string, payload map[string]any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("status %d", resp.StatusCode)
}

func (o *Orchestrator) appendHostsOverride(domain, ip string, dry bool) error {
	dir := o.cfg.EvidenceDir
	if dir == "" {
		dir = "./data/evidence"
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(dir, "sinkhole-hosts.override")
	line := fmt.Sprintf("%s %s  # atde sinkhole dry=%v %s\n", ip, domain, dry, time.Now().UTC().Format(time.RFC3339))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	return err
}

// SimulateP2PPeerPoison records a planned DHT saturation plan without sending packets
// into third-party botnet peer networks (unauthorized network interference).
func (o *Orchestrator) SimulateP2PPeerPoison(botnet string, c2IPs []string, sinkholeIP string) {
	o.log.Info("p2p peer poison SIMULATION only",
		"botnet", botnet,
		"sinkhole", sinkholeIP,
		"peers", len(c2IPs),
		"note", "live DHT injection into third-party botnets is not implemented",
	)
	dir := o.cfg.EvidenceDir
	if dir == "" {
		dir = "./data/evidence"
	}
	_ = os.MkdirAll(dir, 0o750)
	path := filepath.Join(dir, fmt.Sprintf("p2p-poison-sim-%s.json", time.Now().UTC().Format("20060102150405")))
	raw, _ := json.MarshalIndent(map[string]any{
		"mode":        "simulate_only",
		"botnet":      botnet,
		"sinkhole_ip": sinkholeIP,
		"c2_ips":      c2IPs,
		"fake_peers":  500,
		"note":        "Would advertise sinkhole nodes via owned research harnesses only. No live Mirai/Hajime DHT floods.",
		"at":          time.Now().UTC().Format(time.RFC3339),
	}, "", "  ")
	_ = os.WriteFile(path, raw, 0o600)
	for _, ip := range c2IPs {
		o.log.Info("dht inject plan logged", "peer", ip, "fake_nodes", 500, "sinkhole", sinkholeIP)
	}
}

func (o *Orchestrator) serveListener(ctx context.Context) {
	addr := o.cfg.ListenAddr
	if addr == "" {
		addr = ":9080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", o.captureHeartbeat)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sh, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sh)
	}()
	o.log.Info("sinkhole listener", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		o.log.Error("sinkhole listener", "err", err)
	}
}

func (o *Orchestrator) captureHeartbeat(w http.ResponseWriter, r *http.Request) {
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	o.mu.Lock()
	o.hits[ip]++
	n := o.hits[ip]
	o.mu.Unlock()
	o.log.Info("c2 heartbeat neutralized", "infected_host", ip, "hits", n, "path", r.URL.Path, "ua", r.UserAgent())
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(".")) // inert response — no commands
}

func (o *Orchestrator) persistRules() error {
	dir := o.cfg.EvidenceDir
	if dir == "" {
		dir = "./data/evidence"
	}
	_ = os.MkdirAll(dir, 0o750)
	o.mu.Lock()
	defer o.mu.Unlock()
	raw, _ := json.MarshalIndent(o.rules, "", "  ")
	return os.WriteFile(filepath.Join(dir, "sinkhole-rules.json"), raw, 0o600)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
