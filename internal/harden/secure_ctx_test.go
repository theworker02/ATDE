package harden_test

import (
	"log/slog"
	"testing"

	"github.com/theworker02/blind-botnet/v2/internal/harden"
)

func TestZeroizeMemory(t *testing.T) {
	sc := harden.NewSecureContext()
	sc.SetSecret("master", []byte("super-secret-api-key-value"))
	sc.SetSecret("nats", []byte("nats-auth-token-xyz"))
	sc.ZeroizeMemory()
	// After zeroize, buffers should be nil / empty — cannot assert prior contents.
	if sc.MasterAPIKey != nil && len(sc.MasterAPIKey) > 0 {
		for _, b := range sc.MasterAPIKey {
			if b != 0 {
				t.Fatal("master key not zeroized")
			}
		}
	}
	_ = slog.Default()
}
