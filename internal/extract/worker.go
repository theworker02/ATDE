package extract

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/theworker02/ATDE/v2/internal/catch"
	"github.com/theworker02/ATDE/v2/internal/extract/indicators"
	"github.com/theworker02/ATDE/v2/internal/ingest/rules"
	"github.com/theworker02/ATDE/v2/internal/models"
	"github.com/theworker02/ATDE/v2/internal/natsbus"
)

// Worker consumes raw CT/honeypot events and publishes artifact.extracted.
type Worker struct {
	bus   *natsbus.Bus
	rules *rules.Engine
	log   *slog.Logger
	hc    *http.Client
}

func NewWorker(bus *natsbus.Bus, brands []string, log *slog.Logger) *Worker {
	return &Worker{
		bus:   bus,
		rules: rules.New(brands),
		log:   log,
		hc:    &http.Client{Timeout: 20 * time.Second},
	}
}

func (w *Worker) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() {
		errCh <- w.bus.Consume(ctx, models.SubjectRawCT, "EXTRACT_CT", "extract_workers", w.handleRawCT)
	}()
	go func() {
		errCh <- w.bus.Consume(ctx, models.SubjectRawHoneypot, "EXTRACT_HP", "extract_workers", w.handleHoneypot)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (w *Worker) handleRawCT(data []byte) error {
	var evt models.RawCTEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return fmt.Errorf("unmarshal ct: %w", err)
	}
	domain := evt.Data.Domain
	brand := w.rules.DetectBrand(domain)
	threatType := rules.ThreatTypeFromRule(evt.MatchedRule)

	// Attempt light fetch of landing page for IoC extraction (no JS execution).
	var raw []byte
	url := "http://" + domain
	if body, err := w.fetch(url); err == nil {
		raw = body
	}
	decoded := indicators.DecodeLight(raw)
	_, inds, snips := indicators.Extract(decoded)

	iocs := toExtractedIOCs(inds)
	if len(iocs.ExfilEndpoints) == 0 {
		iocs.ExfilEndpoints = append(iocs.ExfilEndpoints, "https://"+domain+"/")
	}

	conf := 0.75
	if brand != "" {
		conf = 0.9
	}
	if len(iocs.TelegramBotTokens) > 0 || len(iocs.Webhooks) > 0 {
		conf = 0.95
	}

	art := models.ArtifactExtracted{
		ID:              "evt_art_" + time.Now().UTC().Format("20060102150405.000000"),
		ParentID:        evt.ID,
		Timestamp:       time.Now().UTC(),
		ThreatType:      threatType,
		TargetBrand:     rules.FormatBrandLabel(brand),
		TargetDomain:    domain,
		ExtractedIOCs:   iocs,
		ConfidenceScore: conf,
		Snippets:        snips,
	}
	out, err := json.Marshal(art)
	if err != nil {
		return err
	}
	_, err = w.bus.Publish(models.SubjectExtracted, out)
	if err == nil {
		w.log.Info("artifact extracted", "domain", domain, "id", art.ID, "confidence", conf)
	}
	return err
}

func (w *Worker) handleHoneypot(data []byte) error {
	var evt models.RawHoneypotEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return fmt.Errorf("unmarshal honeypot: %w", err)
	}
	raw, _ := base64.StdEncoding.DecodeString(evt.Data.BodyB64)
	decoded := indicators.DecodeLight(raw)
	_, inds, snips := indicators.Extract(decoded)
	iocs := toExtractedIOCs(inds)
	ip := catch.StripPort(evt.Data.RemoteAddr)
	if ip != "" && net.ParseIP(ip) != nil {
		iocs.DropIPs = appendUnique(iocs.DropIPs, ip)
	}

	// Interactive probe against a decoy is high-confidence hostile activity.
	domain := "honeypot-capture"
	conf := 0.9
	if len(inds) > 0 {
		conf = 0.95
	}
	art := models.ArtifactExtracted{
		ID: "evt_art_" + time.Now().UTC().Format("20060102150405.000000"),
		ParentID: evt.ID, Timestamp: time.Now().UTC(),
		ThreatType: "honeypot_payload", TargetDomain: domain,
		ExtractedIOCs: iocs, ConfidenceScore: conf, Snippets: snips,
	}
	out, _ := json.Marshal(art)
	_, err := w.bus.Publish(models.SubjectExtracted, out)
	if err == nil {
		w.log.Info("honeypot artifact", "id", art.ID, "ip", ip, "confidence", conf)
	}
	return err
}

func (w *Worker) fetch(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ATDE-Extractor/1.0")
	resp, err := w.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

func toExtractedIOCs(inds []indicators.Indicator) models.ExtractedIOCs {
	var out models.ExtractedIOCs
	for _, ind := range inds {
		switch ind.Type {
		case "telegram_token":
			out.TelegramBotTokens = appendUnique(out.TelegramBotTokens, ind.Value)
		case "telegram_chat":
			out.TelegramChatIDs = appendUnique(out.TelegramChatIDs, ind.Value)
		case "c2_url":
			out.ExfilEndpoints = appendUnique(out.ExfilEndpoints, ind.Value)
		case "c2_ip":
			out.DropIPs = appendUnique(out.DropIPs, ind.Value)
		case "wallet_btc":
			out.WalletsBTC = appendUnique(out.WalletsBTC, ind.Value)
		case "wallet_eth":
			out.WalletsETH = appendUnique(out.WalletsETH, ind.Value)
		case "wallet_sol":
			out.WalletsSOL = appendUnique(out.WalletsSOL, ind.Value)
		case "webhook_discord", "webhook_slack":
			out.Webhooks = appendUnique(out.Webhooks, ind.Value)
		}
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

// PayloadHash returns sha256 of bytes (exported for evidence).
func PayloadHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
