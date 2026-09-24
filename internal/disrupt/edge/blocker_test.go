package edge

import (
	"context"
	"testing"
)

func TestEnforceContainment_BelowScore(t *testing.T) {
	b := New(testEdgeCfg(false), testLog())
	res := b.EnforceContainment(context.Background(), "198.51.100.10", "test", 0.5, true)
	if res.LocalOK || !res.LocalSkipped {
		t.Fatalf("expected skip below score: %+v", res)
	}
}

func TestEnforceContainment_PrivateSkipped(t *testing.T) {
	b := New(testEdgeCfg(true), testLog())
	res := b.EnforceContainment(context.Background(), "127.0.0.1", "test", 0.9, true)
	if res.LocalOK || !res.LocalSkipped {
		t.Fatalf("expected private skip: %+v", res)
	}
}

func TestEnforceContainment_LocalDryRun(t *testing.T) {
	b := New(testEdgeCfg(true), testLog())
	// Public IP + dry-run → BlockIP succeeds without touching the OS.
	res := b.EnforceContainment(context.Background(), "8.8.8.8", "honeypot", 0.9, true)
	if !res.LocalOK {
		t.Fatalf("expected local dry-run OK: %+v", res)
	}
	if res.LocalSkipped {
		t.Fatalf("should not skip public IP in dry-run: %+v", res)
	}
}

func TestSanitizeArg(t *testing.T) {
	got := sanitizeArg("1.2.3.4; rm -rf /")
	if got != "1.2.3.4__rm_-rf__" && got != "1.2.3.4_rm_-rf_" {
		// only alnum . - _ : allowed
		for _, r := range got {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_', r == ':':
			default:
				t.Fatalf("unsafe char in %q", got)
			}
		}
	}
}
