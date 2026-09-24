package active

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/theworker02/blind-botnet/internal/catch"
	"github.com/theworker02/blind-botnet/internal/config"
	"github.com/theworker02/blind-botnet/internal/disrupt/edge"
	"github.com/theworker02/blind-botnet/internal/disrupt/poison"
	"github.com/theworker02/blind-botnet/internal/models"
	"github.com/theworker02/blind-botnet/internal/natsbus"
)

// Controller is the Phase 4 disruption dispatcher.
// It consumes extracted artifacts + honeypot hits, emits disrupt events,
// runs poison simulation (evidence-only), and applies owned-edge blocks.
type Controller struct {
	bus    *natsbus.Bus
	cfg    config.ActiveDefenseConfig
	dryRun bool
	log    *slog.Logger
	edge   *edge.Blocker
	poison *poison.Generator
	ledger *catch.Ledger
}

func New(bus *natsbus.Bus, cfg config.ActiveDefenseConfig, evidenceDir string, dryRun bool, log *slog.Logger) *Controller {
	return &Controller{
		bus:    bus,
		cfg:    cfg,
		dryRun: dryRun || cfg.DryRun,
		log:    log,
		edge:   edge.New(cfg.Edge, log),
		poison: poison.New(evidenceDir, log),
		ledger: catch.New("./data/caught"),
	}
}

func (c *Controller) Run(ctx context.Context) error {
	if !c.cfg.Enabled {
		c.log.Info("active defense controller disabled")
		<-ctx.Done()
		return ctx.Err()
	}
	errCh := make(chan error, 3)
	go func() {
		errCh <- c.bus.Consume(ctx, models.SubjectExtracted, "ACTIVE_EXTRACT", "active_workers", c.onExtracted)
	}()
	go func() {
		errCh <- c.bus.Consume(ctx, models.SubjectRawHoneypot, "ACTIVE_HP", "active_workers", c.onHoneypot)
	}()
	go func() {
		errCh <- c.bus.Consume(ctx, models.SubjectDisrupt, "ACTIVE_EDGE", "firewall_workers", c.onDisrupt)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (c *Controller) onExtracted(data []byte) error {
	var art models.ArtifactExtracted
	if err := json.Unmarshal(data, &art); err != nil {
		return fmt.Errorf("unmarshal artifact: %w", err)
	}
	if art.ConfidenceScore < c.cfg.MinConfidence {
		return nil
	}

	// Simulate noise injection for detected exfil channels (no live third-party posts).
	if c.cfg.Poison.Enabled {
		if len(art.ExtractedIOCs.TelegramBotTokens) > 0 {
			token := art.ExtractedIOCs.TelegramBotTokens[0]
			chat := ""
			if len(art.ExtractedIOCs.TelegramChatIDs) > 0 {
				chat = art.ExtractedIOCs.TelegramChatIDs[0]
			}
			evt, _, err := c.poison.SimulateBatch(art.ID, "telegram", token+"|"+chat, c.cfg.Poison.BatchSize)
			if err != nil {
				c.log.Error("poison simulate failed", "err", err)
			} else {
				_ = c.publishDisrupt(evt)
			}
		}
		for _, wh := range art.ExtractedIOCs.Webhooks {
			evt, _, err := c.poison.SimulateBatch(art.ID, "webhook", wh, c.cfg.Poison.BatchSize)
			if err != nil {
				c.log.Error("poison simulate failed", "err", err)
				continue
			}
			_ = c.publishDisrupt(evt)
		}
	}

	// Block drop IPs at owned edge when present.
	for _, ip := range art.ExtractedIOCs.DropIPs {
		ip = stripPort(ip)
		if net.ParseIP(ip) == nil {
			continue
		}
		evt := models.DisruptionEvent{
			ID:        "evt_dsr_" + time.Now().UTC().Format("20060102150405.000000"),
			ParentID:  art.ID,
			Timestamp: time.Now().UTC(),
			SourceIP:  ip,
			Reason:    "extracted_drop_ip:" + art.ThreatType,
			Action:    models.DisruptActionBlock,
			Channels:  []string{"cloudflare", "local"},
			DryRun:    c.dryRun,
		}
		if err := c.publishDisrupt(evt); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) onHoneypot(data []byte) error {
	var hp models.RawHoneypotEvent
	if err := json.Unmarshal(data, &hp); err != nil {
		return fmt.Errorf("unmarshal honeypot: %w", err)
	}
	ip := stripPort(hp.Data.RemoteAddr)
	if net.ParseIP(ip) == nil {
		return nil
	}

	// Emit tarpit acknowledgment + edge block for scanners hitting decoys.
	tarpitEvt := models.DisruptionEvent{
		ID:        "evt_dsr_" + time.Now().UTC().Format("20060102150405.000000"),
		ParentID:  hp.ID,
		Timestamp: time.Now().UTC(),
		SourceIP:  ip,
		Reason:    fmt.Sprintf("honeypot_%s:%s", hp.Data.Service, hp.Data.Path),
		Action:    models.DisruptActionTarpit,
		Channels:  []string{"honeypot"},
		Meta:      map[string]any{"ua": hp.Data.UserAgent},
		DryRun:    c.dryRun,
	}
	_ = c.publishDisrupt(tarpitEvt)

	if c.cfg.Edge.Enabled {
		blockEvt := models.DisruptionEvent{
			ID:        "evt_dsr_" + time.Now().UTC().Format("20060102150405.000000"),
			ParentID:  hp.ID,
			Timestamp: time.Now().UTC(),
			SourceIP:  ip,
			Reason:    "honeypot_interaction",
			Action:    models.DisruptActionBlock,
			Channels:  []string{"cloudflare", "aws_waf", "local"},
			DryRun:    c.dryRun,
		}
		return c.publishDisrupt(blockEvt)
	}
	return nil
}

func (c *Controller) onDisrupt(data []byte) error {
	var evt models.DisruptionEvent
	if err := json.Unmarshal(data, &evt); err != nil {
		return fmt.Errorf("unmarshal disrupt: %w", err)
	}
	switch evt.Action {
	case models.DisruptActionBlock:
		if !c.cfg.Edge.Enabled {
			c.log.Debug("edge isolation disabled; skip block", "id", evt.ID)
			return nil
		}
		res := c.edge.EnforceContainment(context.Background(), evt.SourceIP, evt.Reason, 0.9, c.dryRun || evt.DryRun)
		actions := []string{"recorded", "edge_block_attempt"}
		if res.LocalOK {
			actions = append(actions, "local_firewall")
		}
		for _, p := range res.CloudTried {
			actions = append(actions, p)
		}
		if c.ledger != nil {
			_ = c.ledger.Record(catch.Record{
				ID:       "catch_block_" + evt.ID,
				CaughtAt: time.Now().UTC(),
				Source:   "active",
				IP:       evt.SourceIP,
				Reason:   evt.Reason,
				Actions:  actions,
				Blocked:  res.LocalOK || len(res.CloudTried) > len(res.CloudErrors),
				Meta: map[string]string{
					"channels":      strings.Join(evt.Channels, ","),
					"local_ok":      fmt.Sprintf("%v", res.LocalOK),
					"local_skipped": fmt.Sprintf("%v", res.LocalSkipped),
					"cloud_errors":  fmt.Sprintf("%d", len(res.CloudErrors)),
				},
			})
		}
		return nil // fail-soft: never abort disrupt consumer on cloud failures
	case models.DisruptActionPoison:
		// Already simulated at emit time; nothing to send outbound.
		c.log.Info("poison action acknowledged (simulated only)", "id", evt.ID, "target", evt.Target)
		return nil
	case models.DisruptActionTarpit:
		c.log.Info("tarpit action noted", "id", evt.ID, "ip", evt.SourceIP)
		return nil
	default:
		c.log.Warn("unknown disrupt action", "action", evt.Action)
		return nil
	}
}

func (c *Controller) publishDisrupt(evt models.DisruptionEvent) error {
	raw, err := json.Marshal(evt)
	if err != nil {
		return err
	}
	_, err = c.bus.Publish(models.SubjectDisrupt, raw)
	if err == nil {
		c.log.Info("disrupt published", "id", evt.ID, "action", evt.Action, "ip", evt.SourceIP, "dry_run", evt.DryRun)
	}
	return err
}

func stripPort(addr string) string {
	addr = strings.TrimSpace(addr)
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	// IPv6 without brackets or bare IP
	return strings.Trim(addr, "[]")
}
