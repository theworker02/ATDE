package poison

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/theworker02/blind-botnet/v2/internal/models"
)

// Generator builds realistic synthetic credentials for evidence / simulation.
// It does NOT send traffic to Telegram, Discord, Slack, or other third-party
// APIs using stolen tokens — that would be unauthorized access.
type Generator struct {
	firstNames []string
	lastNames  []string
	domains    []string
	log        *slog.Logger
	evidenceDir string
}

func New(evidenceDir string, log *slog.Logger) *Generator {
	return &Generator{
		firstNames:  []string{"James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda"},
		lastNames:   []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis"},
		domains:     []string{"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com"},
		log:         log,
		evidenceDir: evidenceDir,
	}
}

func (g *Generator) FakeCredential() (email, password string) {
	fn := g.firstNames[rnd(len(g.firstNames))]
	ln := g.lastNames[rnd(len(g.lastNames))]
	domain := g.domains[rnd(len(g.domains))]
	email = fmt.Sprintf("%s.%s%d@%s", strings.ToLower(fn), strings.ToLower(ln), rnd(999), domain)
	password = fmt.Sprintf("%s%s!%d", fn, ln, rnd(9999))
	return email, password
}

// SimulateBatch generates synthetic noise and writes it under evidenceDir.
// Returns a DisruptionEvent marked simulated=true.
func (g *Generator) SimulateBatch(parentID, channel, targetHint string, count int) (models.DisruptionEvent, string, error) {
	if count <= 0 {
		count = 50
	}
	if count > 500 {
		count = 500 // hard cap for local evidence artifacts
	}
	now := time.Now().UTC()
	type row struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		IP       string `json:"ip"`
		UA       string `json:"ua"`
	}
	batch := make([]row, 0, count)
	for i := 0; i < count; i++ {
		em, pw := g.FakeCredential()
		batch = append(batch, row{
			Email: em, Password: pw,
			IP: fmt.Sprintf("192.0.2.%d", rnd(250)),
			UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		})
	}

	if err := os.MkdirAll(g.evidenceDir, 0o750); err != nil {
		return models.DisruptionEvent{}, "", err
	}
	id := "evt_dsr_" + now.Format("20060102150405.000000")
	path := filepath.Join(g.evidenceDir, id+"-poison-sim.json")
	raw, _ := json.MarshalIndent(map[string]any{
		"note": "SIMULATION ONLY — payloads were NOT sent to third-party exfil APIs. " +
			"Live use of stolen bot tokens/webhooks is unauthorized access and is not implemented.",
		"channel":     channel,
		"target_hint": redactTarget(targetHint),
		"parent_id":   parentID,
		"count":       count,
		"generated_at": now.Format(time.RFC3339),
		"batch":       batch,
	}, "", "  ")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return models.DisruptionEvent{}, "", err
	}

	g.log.Info("poison simulation written",
		"path", path,
		"channel", channel,
		"count", count,
		"target", redactTarget(targetHint),
	)

	evt := models.DisruptionEvent{
		ID:        id,
		ParentID:  parentID,
		Timestamp: now,
		Reason:    "exfil_endpoint_detected",
		Action:    models.DisruptActionPoison,
		Target:    redactTarget(targetHint),
		Channels:  []string{channel},
		Meta: map[string]any{
			"batch_size":    count,
			"evidence_path": path,
			"mode":          "simulate_only",
		},
		DryRun:    true,
		Simulated: true,
	}
	return evt, path, nil
}

func redactTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(none)"
	}
	// Redact telegram tokens: keep prefix only
	if i := strings.Index(s, ":"); i > 0 && i < 15 {
		return s[:min(10, len(s))] + "...[REDACTED]"
	}
	if len(s) > 48 {
		return s[:24] + "...[REDACTED]"
	}
	return s
}

func rnd(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// SessionToken returns a random hex session-looking string.
func SessionToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
