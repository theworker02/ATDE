package enrich

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/theworker02/blind-botnet/v2/internal/catch"
	"github.com/theworker02/blind-botnet/v2/internal/models"
	"github.com/theworker02/blind-botnet/v2/internal/natsbus"
	"github.com/theworker02/blind-botnet/v2/internal/trace/infra"
)

// Worker consumes artifact.extracted and publishes action.takedown packages.
type Worker struct {
	bus           *natsbus.Bus
	infra         *infra.Grapher
	log           *slog.Logger
	minConfidence float64
	dryRun        bool
	ledger        *catch.Ledger
}

func New(bus *natsbus.Bus, infraG *infra.Grapher, minConfidence float64, dryRun bool, log *slog.Logger) *Worker {
	return &Worker{bus: bus, infra: infraG, minConfidence: minConfidence, dryRun: dryRun, log: log, ledger: catch.New("./data/caught")}
}

func (w *Worker) Run(ctx context.Context) error {
	return w.bus.Consume(ctx, models.SubjectExtracted, "ENRICH_ART", "enrich_workers", w.handle)
}

func (w *Worker) handle(data []byte) error {
	var art models.ArtifactExtracted
	if err := json.Unmarshal(data, &art); err != nil {
		return fmt.Errorf("unmarshal artifact: %w", err)
	}
	if art.ConfidenceScore < w.minConfidence {
		w.log.Info("skip low confidence", "id", art.ID, "score", art.ConfidenceScore)
		return nil
	}

	target := models.TakedownTarget{Domain: art.TargetDomain}
	if len(art.ExtractedIOCs.DropIPs) > 0 {
		target.IP = art.ExtractedIOCs.DropIPs[0]
	}

	if w.infra != nil && art.TargetDomain != "" && art.TargetDomain != "honeypot-capture" {
		nodes, _, sum := w.infra.MapHost(context.Background(), art.TargetDomain)
		w.log.Debug("infra map", "summary", sum)
		for _, n := range nodes {
			switch n.Kind {
			case "ip":
				if target.IP == "" {
					if ip, ok := n.Attrs["ip"].(string); ok {
						target.IP = ip
					}
				}
			case "asn":
				if asn, ok := n.Attrs["asn"].(string); ok {
					target.ASN = asn
				}
				if org, ok := n.Attrs["org"].(string); ok {
					target.HostingProvider = org
				}
			case "host":
				if rh, ok := n.Attrs["registrar_hint"].(string); ok {
					target.Registrar = rh
				}
			}
		}
		if target.IP == "" {
			if ips, err := net.LookupHost(art.TargetDomain); err == nil && len(ips) > 0 {
				target.IP = ips[0]
			}
		}
	}

	exfil := detectExfil(art.ExtractedIOCs)
	harvester := firstOr(art.ExtractedIOCs.ExfilEndpoints, "https://"+art.TargetDomain+"/login")
	title := fmt.Sprintf("Active Phishing Domain Impersonating %s", displayBrand(art.TargetBrand))
	if art.TargetBrand == "" {
		title = "Active Malicious Infrastructure Detected"
	}

	hash := sha256.Sum256([]byte(art.ID + art.TargetDomain))
	evt := models.TakedownEvent{
		ID:         "evt_tkd_" + time.Now().UTC().Format("20060102150405.000000"),
		ArtifactID: art.ID,
		Timestamp:  time.Now().UTC(),
		Target:     target,
		EvidenceSummary: models.EvidenceSummary{
			Title:              title,
			HarvesterURL:       harvester,
			ExfiltrationMethod: exfil,
			PCAPHashSHA256:     hex.EncodeToString(hash[:]),
		},
		DispatchTargets: []string{
			"google_safe_browsing",
			"hosting_provider_abuse_api",
			"cloudflare_abuse",
		},
		DryRun: w.dryRun,
	}
	out, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	if _, err := w.bus.Publish(models.SubjectTakedown, out); err != nil {
		return err
	}
	w.log.Info("takedown queued", "id", evt.ID, "domain", target.Domain, "dry_run", w.dryRun)

	if w.ledger != nil {
		ip := target.IP
		if ip == "" && len(art.ExtractedIOCs.DropIPs) > 0 {
			ip = art.ExtractedIOCs.DropIPs[0]
		}
		if ip != "" || (art.TargetDomain != "" && art.TargetDomain != "honeypot-capture") {
			if ip == "" {
				ip = "domain:" + art.TargetDomain
			}
			_ = w.ledger.Record(catch.Record{
				ID:       "catch_" + evt.ID,
				CaughtAt: time.Now().UTC(),
				Source:   "enrich",
				IP:       catch.StripPort(ip),
				Reason:   title,
				Actions:  []string{"recorded", "takedown_queued", "abuse_package"},
				Meta: map[string]string{
					"domain":     art.TargetDomain,
					"threat":     art.ThreatType,
					"confidence": fmt.Sprintf("%.2f", art.ConfidenceScore),
				},
			})
		}
	}

	// Fan-out: botnet blinding + autonomous intel publish
	_ = w.publishSinkhole(art, target)
	_ = w.publishIntel(art, target, title, exfil)
	return nil
}

func (w *Worker) publishSinkhole(art models.ArtifactExtracted, target models.TakedownTarget) error {
	domains := []string{}
	if art.TargetDomain != "" && art.TargetDomain != "honeypot-capture" {
		domains = append(domains, art.TargetDomain)
	}
	for _, u := range art.ExtractedIOCs.ExfilEndpoints {
		if host := hostFromURL(u); host != "" {
			domains = append(domains, host)
		}
	}
	ips := append([]string{}, art.ExtractedIOCs.DropIPs...)
	if target.IP != "" {
		ips = append(ips, target.IP)
	}
	if len(domains) == 0 && len(ips) == 0 {
		return nil
	}
	proto := "http"
	name := "unknown"
	lower := strings.ToLower(art.ThreatType)
	if strings.Contains(lower, "p2p") || strings.Contains(lower, "mirai") || strings.Contains(lower, "hajime") {
		proto = "p2p_dht"
		name = art.ThreatType
	}
	evt := models.SinkholeEvent{
		ID:         "evt_snk_" + time.Now().UTC().Format("20060102150405.000000"),
		ParentID:   art.ID,
		Timestamp:  time.Now().UTC(),
		BotnetName: name,
		C2Domains:  unique(domains),
		C2IPs:      unique(ips),
		Protocol:   proto,
		SinkholeIP: "",
		DryRun:     w.dryRun,
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	_, err = w.bus.Publish(models.SubjectSinkhole, raw)
	if err == nil {
		w.log.Info("sinkhole queued", "id", evt.ID, "domains", len(evt.C2Domains))
	}
	return err
}

func (w *Worker) publishIntel(art models.ArtifactExtracted, target models.TakedownTarget, title, exfil string) error {
	var iocs []string
	if art.TargetDomain != "" {
		iocs = append(iocs, art.TargetDomain)
	}
	if target.IP != "" {
		iocs = append(iocs, target.IP)
	}
	iocs = append(iocs, art.ExtractedIOCs.ExfilEndpoints...)
	iocs = append(iocs, art.ExtractedIOCs.DropIPs...)
	iocs = append(iocs, art.ExtractedIOCs.Webhooks...)

	attacker := target.IP
	if attacker == "" && len(art.ExtractedIOCs.DropIPs) > 0 {
		attacker = art.ExtractedIOCs.DropIPs[0]
	}
	evt := models.PublishEvent{
		ID:                  "evt_pub_" + time.Now().UTC().Format("20060102150405.000000"),
		ParentID:            art.ID,
		Timestamp:           time.Now().UTC(),
		ThreatType:          art.ThreatType,
		TargetDomain:        art.TargetDomain,
		AttackerIP:          attacker,
		AbuseIPDBCategories: []int{11, 18},
		IOCs:                unique(iocs),
		Summary:             fmt.Sprintf("%s | exfil=%s | confidence=%.2f", title, exfil, art.ConfidenceScore),
		Channels:            []string{"abuseipdb", "misp", "mastodon", "bluesky", "gist"},
		DryRun:              w.dryRun,
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	_, err = w.bus.Publish(models.SubjectPublish, raw)
	if err == nil {
		w.log.Info("publish queued", "id", evt.ID, "ip", attacker)
	}
	return err
}

func hostFromURL(u string) string {
	u = strings.TrimSpace(u)
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func unique(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func detectExfil(i models.ExtractedIOCs) string {
	switch {
	case len(i.TelegramBotTokens) > 0:
		return "Telegram Bot API"
	case len(i.Webhooks) > 0:
		return "Webhook Exfiltration"
	case len(i.WalletsETH)+len(i.WalletsBTC)+len(i.WalletsSOL) > 0:
		return "Cryptocurrency Wallet"
	case len(i.ExfilEndpoints) > 0:
		return "HTTP Exfil Endpoint"
	default:
		return "Unknown / Domain Heuristic"
	}
}

func firstOr(xs []string, fallback string) string {
	if len(xs) > 0 && xs[0] != "" {
		return xs[0]
	}
	return fallback
}

func displayBrand(b string) string {
	if b == "" {
		return "Target Brand"
	}
	return strings.ReplaceAll(b, "_", " ")
}
