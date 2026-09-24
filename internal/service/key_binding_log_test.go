package service

import (
	"log/slog"
	"strings"
	"testing"

	"github.com/chuckyatsuk/plate/internal/auth"
)

// Boot logs one WARN per trusted key that can still sign for any account, and
// names every bound key — so an unbound key is never silent.
func TestLogKeyBindings_WarnsEveryUnboundKey(t *testing.T) {
	setProdShapedKeys(t)
	t.Setenv("PLATE_JWT_KEY_ACCOUNTS", "uri=uriaran,registry=reg_*")
	cfg, err := LoadEnv()
	if err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	LogKeyBindings(slog.New(slog.NewTextHandler(&buf, nil)), cfg.Verifier)
	out := buf.String()
	for _, unbound := range []string{auth.LegacyKeyName, "files", "registry-ci", "registry-prod"} {
		if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "key="+unbound) {
			t.Errorf("no WARN naming unbound key %q:\n%s", unbound, out)
		}
	}
	if strings.Count(out, "level=WARN") != 4 {
		t.Errorf("want exactly 4 WARN lines (one per unbound key):\n%s", out)
	}
	if !strings.Contains(out, "key=registry accounts=reg_*") || !strings.Contains(out, "key=uri accounts=uriaran") {
		t.Errorf("bound keys not reported:\n%s", out)
	}
}
