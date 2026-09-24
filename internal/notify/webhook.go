package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/theworker02/blind-botnet/internal/catch"
)

// Webhook posts catch records to an operator-owned URL (Slack/Discord/generic JSON).
type Webhook struct {
	URL    string
	Token  string // optional Bearer
	Client *http.Client
	Log    *slog.Logger
}

func NewWebhook(url, token string, log *slog.Logger) *Webhook {
	if log == nil {
		log = slog.Default()
	}
	return &Webhook{
		URL:    url,
		Token:  token,
		Client: &http.Client{Timeout: 8 * time.Second},
		Log:    log,
	}
}

// Handle implements catch.OnRecord.
func (w *Webhook) Handle(r catch.Record) {
	if w == nil || w.URL == "" {
		return
	}
	payload := map[string]any{
		"text": fmtText(r),
		"atde": map[string]any{
			"id":       r.ID,
			"ip":       r.IP,
			"source":   r.Source,
			"service":  r.Service,
			"path":     r.Path,
			"reason":   r.Reason,
			"actions":  r.Actions,
			"caught_at": r.CaughtAt.UTC().Format(time.RFC3339),
		},
	}
	raw, _ := json.Marshal(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(raw))
	if err != nil {
		w.Log.Warn("webhook build", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ATDE-notify/0.1")
	if w.Token != "" {
		req.Header.Set("Authorization", "Bearer "+w.Token)
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		w.Log.Warn("webhook post", "err", err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		w.Log.Warn("webhook status", "code", resp.StatusCode)
	}
}

func fmtText(r catch.Record) string {
	return "ATDE catch: " + r.IP + " via " + r.Source + " " + r.Service + " " + r.Path + " (" + r.Reason + ")"
}
