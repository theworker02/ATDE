package natsbus

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/theworker02/blind-botnet/v2/internal/models"
)

// Bus wraps NATS JetStream for the THREAT_PIPELINE stream.
type Bus struct {
	nc  *nats.Conn
	js  nats.JetStreamContext
	log *slog.Logger
}

func Connect(url string, log *slog.Logger) (*Bus, error) {
	if url == "" {
		url = nats.DefaultURL
	}
	nc, err := nats.Connect(url,
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.Name("atde"),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	b := &Bus{nc: nc, js: js, log: log}
	if err := b.EnsureStream(); err != nil {
		nc.Close()
		return nil, err
	}
	return b, nil
}

func (b *Bus) Close() {
	if b == nil || b.nc == nil {
		return
	}
	b.nc.Close()
}

func (b *Bus) JS() nats.JetStreamContext { return b.js }

func (b *Bus) NC() *nats.Conn { return b.nc }

func (b *Bus) EnsureStream() error {
	cfg := &nats.StreamConfig{
		Name:      models.StreamName,
		Subjects:  []string{"threat.v1.raw.*", "threat.v1.artifact.*", "threat.v1.action.*"},
		Retention: nats.LimitsPolicy,
		MaxAge:    7 * 24 * time.Hour,
		Storage:   nats.FileStorage,
		Discard:   nats.DiscardOld,
		Duplicates: 2 * time.Minute,
	}
	info, err := b.js.StreamInfo(models.StreamName)
	if err == nats.ErrStreamNotFound {
		_, err = b.js.AddStream(cfg)
		if err != nil {
			return fmt.Errorf("add stream: %w", err)
		}
		b.log.Info("created jetstream", "stream", models.StreamName)
		return nil
	}
	if err != nil {
		return err
	}
	_, err = b.js.UpdateStream(cfg)
	if err != nil && !strings.Contains(err.Error(), "subjects") {
		// Best-effort update; existing stream is fine.
		b.log.Debug("stream update", "err", err, "stream", info.Config.Name)
	}
	return nil
}

// Publish sends raw bytes to a subject.
func (b *Bus) Publish(subject string, data []byte) (*nats.PubAck, error) {
	ack, err := b.js.Publish(subject, data)
	if err != nil {
		return nil, fmt.Errorf("publish %s: %w", subject, err)
	}
	b.log.Debug("published", "subject", subject, "seq", ack.Sequence)
	return ack, nil
}

// PublishDLQ records a failed message for manual analysis.
func (b *Bus) PublishDLQ(subject, errMsg string, payload []byte) {
	evt := models.DLQEvent{
		ID:        "evt_dlq_" + time.Now().UTC().Format("20060102150405.000000"),
		Timestamp: time.Now().UTC(),
		Subject:   subject,
		Error:     errMsg,
		Payload:   string(payload),
	}
	raw, _ := jsonMarshal(evt)
	if _, err := b.js.Publish(models.SubjectDLQ, raw); err != nil {
		b.log.Error("dlq publish failed", "err", err)
	}
}

// Consume binds a durable queue consumer and invokes handler until ctx cancels.
func (b *Bus) Consume(ctx context.Context, subject, durable, queue string, handler func([]byte) error) error {
	sub, err := b.js.QueueSubscribe(subject, queue, func(msg *nats.Msg) {
		if err := handler(msg.Data); err != nil {
			b.log.Error("handler failed", "subject", subject, "err", err)
			b.PublishDLQ(subject, err.Error(), msg.Data)
			_ = msg.Ack() // acknowledge to avoid infinite redelivery; DLQ holds copy
			return
		}
		_ = msg.Ack()
	}, nats.Durable(durable), nats.ManualAck(), nats.AckWait(60*time.Second), nats.DeliverAll())
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", subject, err)
	}
	b.log.Info("consumer ready", "subject", subject, "durable", durable, "queue", queue)
	<-ctx.Done()
	_ = sub.Unsubscribe()
	return ctx.Err()
}

func jsonMarshal(v any) ([]byte, error) {
	return marshalJSON(v)
}
