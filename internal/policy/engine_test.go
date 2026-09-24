package policy

import "testing"

func TestEvaluateTiers(t *testing.T) {
	e := New(DefaultConfig(), nil)
	d := e.Evaluate("203.0.113.10", 20, "probe")
	if d.Tier != TierObserve {
		t.Fatalf("want observe got %s", d.Tier)
	}
	d = e.Evaluate("203.0.113.10", 40, "scan")
	if d.Tier != TierTarpit {
		t.Fatalf("want tarpit got %s", d.Tier)
	}
	// bump hits for local ban
	e.Evaluate("203.0.113.11", 60, "a")
	d = e.Evaluate("203.0.113.11", 60, "b")
	if d.Tier != TierLocalBan {
		t.Fatalf("want local_ban got %s hits=%d", d.Tier, d.HitCount)
	}
	e.Evaluate("203.0.113.12", 80, "1")
	e.Evaluate("203.0.113.12", 80, "2")
	d = e.Evaluate("203.0.113.12", 80, "3")
	if d.Tier != TierCloud {
		t.Fatalf("want cloud got %s", d.Tier)
	}
}
