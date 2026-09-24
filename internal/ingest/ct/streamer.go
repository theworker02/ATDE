package ct

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/theworker02/ATDE/v2/internal/config"
	"github.com/theworker02/ATDE/v2/internal/ingest/rules"
	"github.com/theworker02/ATDE/v2/internal/models"
	"github.com/theworker02/ATDE/v2/internal/natsbus"
)

// Streamer connects to CertStream, applies RuleEngine heuristics, publishes to NATS.
type Streamer struct {
	cfg    config.CTConfig
	rules  *rules.Engine
	bus    *natsbus.Bus
	log    *slog.Logger
}

func New(cfg config.CTConfig, brands []string, bus *natsbus.Bus, log *slog.Logger) *Streamer {
	return &Streamer{
		cfg:   cfg,
		rules: rules.New(brands),
		bus:   bus,
		log:   log,
	}
}

type certStreamMessage struct {
	MessageType string `json:"message_type"`
	Data        struct {
		LeafCert struct {
			AllDomains []string `json:"all_domains"`
			Subject    struct {
				CN string `json:"CN"`
			} `json:"subject"`
			Fingerprint string `json:"fingerprint"`
			Issuer      struct {
				O  string `json:"O"`
				CN string `json:"CN"`
			} `json:"issuer"`
		} `json:"leaf_cert"`
	} `json:"data"`
}

type domainJob struct {
	domain     string
	allDomains []string
	issuer     string
	fp         string
}

func (s *Streamer) Run(ctx context.Context) error {
	if !s.cfg.Enabled {
		s.log.Info("ct streamer disabled")
		return nil
	}

	jobs := make(chan domainJob, s.cfg.QueueSize)
	var wg sync.WaitGroup
	for i := 0; i < s.cfg.Workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}
					s.handleJob(workerID, job)
				}
			}
		}(i)
	}

	defer func() {
		close(jobs)
		wg.Wait()
	}()

	dialer := websocket.Dialer{HandshakeTimeout: 10 * time.Second}
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.session(ctx, &dialer, jobs); err != nil {
			s.log.Warn("ct session ended", "err", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(3 * time.Second):
			}
		}
	}
}

func (s *Streamer) session(ctx context.Context, dialer *websocket.Dialer, jobs chan<- domainJob) error {
	conn, _, err := dialer.DialContext(ctx, s.cfg.WSURL, http.Header{})
	if err != nil {
		return fmt.Errorf("dial certstream: %w", err)
	}
	defer conn.Close()
	s.log.Info("ct streamer connected", "url", s.cfg.WSURL)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		_, message, err := conn.ReadMessage()
		if err != nil {
			return err
		}
		var msg certStreamMessage
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}
		if msg.MessageType != "certificate_update" {
			continue
		}
		domains := msg.Data.LeafCert.AllDomains
		if len(domains) == 0 && msg.Data.LeafCert.Subject.CN != "" {
			domains = []string{msg.Data.LeafCert.Subject.CN}
		}
		issuer := msg.Data.LeafCert.Issuer.O
		if issuer == "" {
			issuer = msg.Data.LeafCert.Issuer.CN
		}
		fp := msg.Data.LeafCert.Fingerprint
		for _, domain := range domains {
			select {
			case jobs <- domainJob{domain: domain, allDomains: domains, issuer: issuer, fp: fp}:
			default:
				// drop under backpressure
			}
		}
	}
}

func (s *Streamer) handleJob(workerID int, job domainJob) {
	assessment := s.rules.Assess(job.domain)
	if !assessment.Suspicious {
		return
	}
	rule := assessment.Rule
	now := time.Now().UTC()
	id := "evt_raw_" + now.Format("20060102150405.000000") + fmt.Sprintf("_%d", workerID)
	fp := job.fp
	if fp == "" {
		sum := sha256.Sum256([]byte(job.domain + job.issuer))
		fp = hex.EncodeToString(sum[:8])
	}
	evt := models.RawCTEvent{
		ID: id, Timestamp: now, Source: "certstream",
		Data: models.CTData{
			Fingerprint: fp, Domain: job.domain, AllDomains: job.allDomains,
			Issuer: job.issuer, SeenAt: now.Unix(),
		},
		MatchedRule: rule,
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		return
	}
	if _, err := s.bus.Publish(models.SubjectRawCT, raw); err != nil {
		s.log.Error("publish ct", "err", err)
		return
	}
	s.log.Info("ct match", "domain", job.domain, "rule", rule, "score", assessment.Score, "signals", assessment.Signals, "worker", workerID)
}
