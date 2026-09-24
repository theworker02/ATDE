package deception

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/theworker02/blind-botnet/internal/catch"
	"github.com/theworker02/blind-botnet/internal/immunize"
	"github.com/theworker02/blind-botnet/internal/models"
	"github.com/theworker02/blind-botnet/internal/natsbus"
)

// ThreatReporter implements Rule 2 (Recorder) + Rule 3 immunization dispatch.
type ThreatReporter struct {
	SIEMWebhook string
	Bus         *natsbus.Bus
	Immunize    *immunize.MultiCloudDispatcher
	Log         *slog.Logger
	DryRun      bool
	hc          *http.Client
	blockScore  int
	ledger      *catch.Ledger
}

func NewThreatReporter(siemURL string, bus *natsbus.Bus, disp *immunize.MultiCloudDispatcher, dryRun bool, log *slog.Logger) *ThreatReporter {
	return &ThreatReporter{
		SIEMWebhook: firstEnv(siemURL, "SIEM_WEBHOOK_URL", "DECEPTION_SIEM_WEBHOOK"),
		Bus:         bus,
		Immunize:    disp,
		Log:         log,
		DryRun:      dryRun,
		hc:          &http.Client{Timeout: 5 * time.Second},
		blockScore:  50,
		ledger:      catch.New("./data/caught"),
	}
}

// RecordAndDispatch logs, publishes to NATS/SIEM, and auto-blocks when risk is high.
func (tr *ThreatReporter) RecordAndDispatch(evt models.AttackEvent) {
	raw, _ := json.Marshal(evt)
	tr.Log.Warn("exploit detected", "event", json.RawMessage(raw))

	actions := []string{"recorded"}
	if evt.RiskScore >= tr.blockScore {
		actions = append(actions, "auto_block_queued")
	}
	if tr.ledger != nil {
		_ = tr.ledger.Record(catch.Record{
			ID:        "catch_" + evt.ID,
			CaughtAt:  evt.Timestamp,
			Source:    "deception",
			IP:        evt.ClientIP,
			Service:   evt.VulnClass,
			Path:      evt.TargetEndpoint,
			Method:    evt.Method,
			UserAgent: evt.UserAgent,
			Reason:    "deception:" + evt.VulnClass,
			Actions:   actions,
			Meta: map[string]string{
				"tool_hint":  evt.ToolHint,
				"risk_score": fmt.Sprintf("%d", evt.RiskScore),
			},
		})
	}

	if tr.Bus != nil {
		if _, err := tr.Bus.Publish(models.SubjectAttack, raw); err != nil {
			tr.Log.Error("publish attack event", "err", err)
		}
		// Also feed honeypot stream for existing pipeline consumers.
		hp := models.RawHoneypotEvent{
			ID:        evt.ID,
			Timestamp: evt.Timestamp,
			Source:    "deception",
			Data: models.HoneypotData{
				Service:    "deception:" + evt.VulnClass,
				RemoteAddr: evt.ClientIP,
				Path:       evt.TargetEndpoint,
				Method:     evt.Method,
				UserAgent:  evt.UserAgent,
				Headers:    evt.HTTPHeaders,
			},
		}
		hraw, _ := json.Marshal(hp)
		_, _ = tr.Bus.Publish(models.SubjectRawHoneypot, hraw)

		if evt.RiskScore >= tr.blockScore {
			disrupt := models.DisruptionEvent{
				ID:        "evt_dsr_" + time.Now().UTC().Format("20060102150405.000000"),
				ParentID:  evt.ID,
				Timestamp: time.Now().UTC(),
				SourceIP:  evt.ClientIP,
				Reason:    "deception:" + evt.VulnClass,
				Action:    models.DisruptActionBlock,
				Channels:  []string{"cloudflare", "aws_waf", "local"},
				DryRun:    tr.DryRun,
				Meta: map[string]any{
					"tool_hint": evt.ToolHint,
					"ja3":       evt.JA3,
					"payload":   truncate(evt.RawPayload, 256),
				},
			}
			draw, _ := json.Marshal(disrupt)
			_, _ = tr.Bus.Publish(models.SubjectDisrupt, draw)
		}
	}

	go tr.sendToSIEM(evt)
	if evt.RiskScore >= tr.blockScore && tr.Immunize != nil {
		go tr.Immunize.AutoBlockIP(context.Background(), evt.ClientIP, evt.VulnClass)
	}
}

func (tr *ThreatReporter) sendToSIEM(evt models.AttackEvent) {
	if tr.SIEMWebhook == "" {
		return
	}
	if tr.DryRun {
		tr.Log.Info("siem dry-run", "url", tr.SIEMWebhook, "ip", evt.ClientIP)
		return
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, tr.SIEMWebhook, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := tr.hc.Do(req)
	if err != nil {
		tr.Log.Error("siem webhook failed", "err", err)
		return
	}
	defer resp.Body.Close()
	tr.Log.Info("siem notified", "status", resp.StatusCode, "ip", evt.ClientIP)
}

func firstEnv(primary string, keys ...string) string {
	if strings.TrimSpace(primary) != "" {
		return strings.TrimSpace(primary)
	}
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
