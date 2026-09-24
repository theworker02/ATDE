package rules_test

import (
	"testing"

	"github.com/theworker02/blind-botnet/internal/ingest/rules"
)

func TestInspectDomain(t *testing.T) {
	re := rules.New([]string{"chase", "paypal", "binance", "google", "microsoft"})

	cases := []struct {
		domain  string
		wantHit bool
	}{
		{"login-chase-security-update.com", true},
		{"verify-paypal-account.net", true},
		{"secure-binance-wallet.xyz", true},
		{"example.com", false},
		{"chase.com", false},
		{"paypa1-login.com", true},
		{"xn--paypal-hack.example", true},
		{"g00gle-secure-login.com", true},
	}
	for _, tc := range cases {
		hit, rule := re.InspectDomain(tc.domain)
		if hit != tc.wantHit {
			t.Fatalf("%s: hit=%v rule=%q wantHit=%v", tc.domain, hit, rule, tc.wantHit)
		}
	}
}

func TestDetectBrand(t *testing.T) {
	re := rules.New([]string{"chase", "paypal"})
	if got := re.DetectBrand("login-chase-security-update.com"); got != "chase" {
		t.Fatalf("got %q", got)
	}
}

func TestAssessSignals(t *testing.T) {
	re := rules.New([]string{"paypal", "coinbase"})
	s := re.Assess("login-paypal-secure-update.com")
	if !s.Suspicious || s.Score < 0.7 {
		t.Fatalf("expected high score phishing: %+v", s)
	}
	if s.Brand != "paypal" {
		t.Fatalf("brand=%q", s.Brand)
	}
	if len(s.Signals) < 2 {
		t.Fatalf("expected multiple signals: %v", s.Signals)
	}
}

func TestAssessBenign(t *testing.T) {
	re := rules.New([]string{"paypal"})
	s := re.Assess("wikipedia.org")
	if s.Suspicious {
		t.Fatalf("wikipedia should not be suspicious: %+v", s)
	}
}

func BenchmarkAssess(b *testing.B) {
	re := rules.New([]string{"chase", "paypal", "binance", "coinbase", "metamask", "appleid", "microsoft", "google"})
	domains := []string{
		"login-chase-security-update.com",
		"example.com",
		"paypa1-verify.net",
		"cdn.cloudflare.com",
		"secure-binance-wallet.xyz",
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = re.Assess(domains[i%len(domains)])
	}
}
