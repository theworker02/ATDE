package ops

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

// Metrics holds process-level counters for diligence demos and ops.
type Metrics struct {
	StartedAt time.Time
	Version   string
	Mode      string

	HoneypotHits   atomic.Uint64
	AuthBurns      atomic.Uint64
	VulnBaitHits   atomic.Uint64
	DisruptBlocks  atomic.Uint64
	LocalBlocksOK  atomic.Uint64
	CloudAttempts  atomic.Uint64
	CloudFailures  atomic.Uint64
	CTMatches      atomic.Uint64
	ArtifactsOut   atomic.Uint64
	PublishJobs    atomic.Uint64
	CatchRecords   atomic.Uint64
}

func NewMetrics(version, mode string) *Metrics {
	return &Metrics{StartedAt: time.Now().UTC(), Version: version, Mode: mode}
}

// Handler serves /healthz, /readyz, /metrics, /v1/status (+ optional catch API / console).
type Handler struct {
	Metrics *Metrics
	Ready   func() bool
	Catch   *CatchAPI
}

func (h *Handler) Mount(mux *http.ServeMux) {
	mux.HandleFunc("/healthz", h.healthz)
	mux.HandleFunc("/readyz", h.readyz)
	mux.HandleFunc("/metrics", h.metrics)
	mux.HandleFunc("/v1/status", h.status)
	mux.Handle("/debug/vars", expvar.Handler())
	if h.Catch != nil {
		h.Catch.Mount(mux)
	}
}

func (h *Handler) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (h *Handler) readyz(w http.ResponseWriter, _ *http.Request) {
	if h.Ready != nil && !h.Ready() {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func (h *Handler) status(w http.ResponseWriter, _ *http.Request) {
	m := h.Metrics
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	payload := map[string]any{
		"service":    "atde",
		"product":    "Autonomous Threat Disruption Engine",
		"version":    m.Version,
		"line":       "2.0",
		"mode":       m.Mode,
		"started_at": m.StartedAt.Format(time.RFC3339),
		"uptime_sec": int(time.Since(m.StartedAt).Seconds()),
		"go":         runtime.Version(),
		"goroutines": runtime.NumGoroutine(),
		"mem_alloc":  ms.Alloc,
		"baits": []string{"http", "ssh", "redis", "telnet", "mysql", "ftp", "smtp", "elasticsearch", "mongodb", "deception"},
		"disruption": []string{"policy", "tarpit", "local_ban", "cloud", "fleet", "siem_export"},
		"counters": map[string]uint64{
			"honeypot_hits":   m.HoneypotHits.Load(),
			"auth_burns":      m.AuthBurns.Load(),
			"vuln_bait_hits":  m.VulnBaitHits.Load(),
			"disrupt_blocks":  m.DisruptBlocks.Load(),
			"local_blocks_ok": m.LocalBlocksOK.Load(),
			"cloud_attempts":  m.CloudAttempts.Load(),
			"cloud_failures":  m.CloudFailures.Load(),
			"ct_matches":      m.CTMatches.Load(),
			"artifacts_out":   m.ArtifactsOut.Load(),
			"publish_jobs":    m.PublishJobs.Load(),
			"catch_records":   m.CatchRecords.Load(),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

// Prometheus text exposition (no external dependency).
func (h *Handler) metrics(w http.ResponseWriter, _ *http.Request) {
	m := h.Metrics
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = fmt.Fprintf(w, "# HELP atde_up 1 if process is up\natde_up 1\n")
	_, _ = fmt.Fprintf(w, "# HELP atde_info Build info\natde_info{version=\"%s\",line=\"2.0\"} 1\n", m.Version)
	_, _ = fmt.Fprintf(w, "# HELP atde_honeypot_hits_total Honeypot hits observed\natde_honeypot_hits_total %d\n", m.HoneypotHits.Load())
	_, _ = fmt.Fprintf(w, "# HELP atde_auth_burns_total Login/MFA attempts burned\natde_auth_burns_total %d\n", m.AuthBurns.Load())
	_, _ = fmt.Fprintf(w, "# HELP atde_vuln_bait_hits_total Juicy-file / vuln-bait hits\natde_vuln_bait_hits_total %d\n", m.VulnBaitHits.Load())
	_, _ = fmt.Fprintf(w, "# HELP atde_disrupt_blocks_total Disrupt block actions\natde_disrupt_blocks_total %d\n", m.DisruptBlocks.Load())
	_, _ = fmt.Fprintf(w, "# HELP atde_local_blocks_ok_total Successful local firewall blocks\natde_local_blocks_ok_total %d\n", m.LocalBlocksOK.Load())
	_, _ = fmt.Fprintf(w, "# HELP atde_cloud_attempts_total Cloud ban attempts\natde_cloud_attempts_total %d\n", m.CloudAttempts.Load())
	_, _ = fmt.Fprintf(w, "# HELP atde_cloud_failures_total Cloud ban failures\natde_cloud_failures_total %d\n", m.CloudFailures.Load())
	_, _ = fmt.Fprintf(w, "# HELP atde_ct_matches_total CT rule matches\natde_ct_matches_total %d\n", m.CTMatches.Load())
	_, _ = fmt.Fprintf(w, "# HELP atde_artifacts_out_total Extracted artifacts published\natde_artifacts_out_total %d\n", m.ArtifactsOut.Load())
	_, _ = fmt.Fprintf(w, "# HELP atde_catch_records_total Catch ledger writes\natde_catch_records_total %d\n", m.CatchRecords.Load())
}

// ListenAndServe starts the ops HTTP server until ctx cancel.
func ListenAndServe(ctx context.Context, addr string, h *Handler) error {
	mux := http.NewServeMux()
	h.Mount(mux)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
		return ctx.Err()
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
