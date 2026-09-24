package indicators_test

import (
	"testing"

	"github.com/theworker02/blind-botnet/v2/internal/extract/indicators"
)

func TestExtractTelegramAndWallet(t *testing.T) {
	raw := []byte(`
var token = "6123456789:AAFgH_xXyZ1234567890abcdefABCDEF12";
chat_id = "-100123456789";
drop = "https://evil.example/api/drop.php";
eth = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb0";
`)
	_, inds, _ := indicators.Extract(raw)
	if len(inds) == 0 {
		t.Fatal("expected indicators")
	}
	var sawToken, sawURL, sawETH bool
	for _, ind := range inds {
		switch ind.Type {
		case "telegram_token":
			sawToken = true
		case "c2_url":
			sawURL = true
		case "wallet_eth":
			sawETH = true
		}
	}
	if !sawToken || !sawURL || !sawETH {
		t.Fatalf("missing expected iocs: token=%v url=%v eth=%v inds=%v", sawToken, sawURL, sawETH, inds)
	}
}
