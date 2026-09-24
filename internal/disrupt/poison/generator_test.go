package poison_test

import (
	"os"
	"path/filepath"
	"testing"

	"log/slog"

	"github.com/theworker02/blind-botnet/internal/disrupt/poison"
	"github.com/theworker02/blind-botnet/internal/models"
)

func TestSimulateBatchDoesNotRequireNetwork(t *testing.T) {
	dir := t.TempDir()
	g := poison.New(dir, slog.Default())
	evt, path, err := g.SimulateBatch("parent1", "telegram", "6123456789:SECRETTOKEN", 10)
	if err != nil {
		t.Fatal(err)
	}
	if !evt.Simulated || evt.Action != models.DisruptActionPoison {
		t.Fatalf("unexpected event: %+v", evt)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if filepath.Ext(path) != ".json" {
		t.Fatalf("expected json evidence, got %s", path)
	}
	if len(raw) < 50 {
		t.Fatal("evidence too small")
	}
}
