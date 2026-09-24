package harden

import (
	"crypto/rand"
	"log/slog"
	"sync"
)

// SecureContext holds sensitive material that must be zeroized on compromise.
type SecureContext struct {
	mu           sync.Mutex
	MasterAPIKey []byte
	NATSAuthKey  []byte
	Extra        map[string][]byte
}

func NewSecureContext() *SecureContext {
	return &SecureContext{Extra: map[string][]byte{}}
}

// SetSecret stores a named secret and overwrites any previous value.
func (sc *SecureContext) SetSecret(name string, value []byte) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if name == "master" {
		zero(sc.MasterAPIKey)
		sc.MasterAPIKey = append([]byte(nil), value...)
		return
	}
	if name == "nats" {
		zero(sc.NATSAuthKey)
		sc.NATSAuthKey = append([]byte(nil), value...)
		return
	}
	if sc.Extra == nil {
		sc.Extra = map[string][]byte{}
	}
	zero(sc.Extra[name])
	sc.Extra[name] = append([]byte(nil), value...)
}

// ZeroizeMemory overwrites all retained secrets before process death.
func (sc *SecureContext) ZeroizeMemory() {
	if sc == nil {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	zero(sc.MasterAPIKey)
	zero(sc.NATSAuthKey)
	for k, v := range sc.Extra {
		zero(v)
		sc.Extra[k] = nil
	}
	sc.MasterAPIKey = nil
	sc.NATSAuthKey = nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	// Extra pass with random noise then zero again (best-effort against residual pages).
	if len(b) > 0 {
		_, _ = rand.Read(b)
		for i := range b {
			b[i] = 0
		}
	}
}

// LockSensitivePages best-effort mlock of secret buffers (platform-specific).
func (sc *SecureContext) LockSensitivePages(log *slog.Logger) {
	if sc == nil {
		return
	}
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for _, buf := range [][]byte{sc.MasterAPIKey, sc.NATSAuthKey} {
		if err := lockPages(buf); err != nil && log != nil {
			log.Debug("mlock skipped", "err", err)
		}
	}
	for _, buf := range sc.Extra {
		_ = lockPages(buf)
	}
}
