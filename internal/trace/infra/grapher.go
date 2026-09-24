package infra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/theworker02/ATDE/v2/internal/config"
)

// Grapher maps domains/IPs to ASN and hosting metadata.
type Grapher struct {
	cfg config.TraceConfig
	log *slog.Logger
	hc  *http.Client
}

func New(cfg config.TraceConfig, log *slog.Logger) *Grapher {
	return &Grapher{
		cfg: cfg,
		log: log,
		hc:  &http.Client{Timeout: 15 * time.Second},
	}
}

// TraceNode is a lightweight graph node used by enrichment (local to avoid old model deps).
type TraceNode struct {
	ID    string
	Kind  string
	Attrs map[string]any
}

type TraceEdge struct {
	From, To, Rel string
	Weight        float64
}

// MapHost resolves DNS and attaches ASN metadata.
func (g *Grapher) MapHost(ctx context.Context, host string) (nodes []TraceNode, edges []TraceEdge, summary string) {
	host = normalizeHost(host)
	if host == "" {
		return nil, nil, ""
	}
	domainID := "domain:" + host
	nodes = append(nodes, TraceNode{ID: domainID, Kind: "domain", Attrs: map[string]any{"host": host}})

	ips, _ := net.DefaultResolver.LookupHost(ctx, host)
	for _, ip := range ips {
		ipID := "ip:" + ip
		nodes = append(nodes, TraceNode{ID: ipID, Kind: "ip", Attrs: map[string]any{"ip": ip}})
		edges = append(edges, TraceEdge{From: domainID, To: ipID, Rel: "resolves", Weight: 1})

		asn, org, err := g.lookupASN(ctx, ip)
		if err != nil {
			g.log.Debug("asn lookup skipped", "ip", ip, "err", err)
			continue
		}
		asnID := "asn:" + asn
		nodes = append(nodes, TraceNode{ID: asnID, Kind: "asn", Attrs: map[string]any{"asn": asn, "org": org}})
		edges = append(edges, TraceEdge{From: ipID, To: asnID, Rel: "hosts", Weight: 1})
	}

	if whois := whoisHint(host); whois != "" {
		nodes = append(nodes, TraceNode{
			ID: "registrar:" + whois, Kind: "host",
			Attrs: map[string]any{"registrar_hint": whois, "domain": host},
		})
	}

	summary = fmt.Sprintf("host=%s ips=%d", host, len(ips))
	return nodes, edges, summary
}

func (g *Grapher) lookupASN(ctx context.Context, ip string) (asn, org string, err error) {
	u := fmt.Sprintf("https://ipapi.co/%s/json/", ip)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "ATDE-InfraGrapher/1.0")
	resp, err := g.hc.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var data struct {
		ASN    string `json:"asn"`
		Org    string `json:"org"`
		Error  bool   `json:"error"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", "", err
	}
	if data.Error {
		return "", "", fmt.Errorf("%s", data.Reason)
	}
	return data.ASN, data.Org, nil
}

func whoisHint(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) < 2 {
		return ""
	}
	switch parts[len(parts)-1] {
	case "tk", "ml", "ga", "cf", "gq":
		return "freenom-legacy"
	case "top", "xyz", "click", "loan":
		return "high-abuse-tld"
	default:
		return ""
	}
}

func normalizeHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if strings.HasPrefix(h, "http://") || strings.HasPrefix(h, "https://") {
		u, err := url.Parse(h)
		if err == nil {
			h = u.Hostname()
		}
	}
	return strings.TrimPrefix(h, "*.")
}
