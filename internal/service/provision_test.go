package service

import (
	"encoding/json"
	"net/http"
	"testing"

	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// PUT /v1/account — the gates, at the handler. The SQL (idempotent, never
// overwrites) is proven against real Postgres in test/account_provisioning_test.go.

func TestProvisionAccount_Gates(t *testing.T) {
	k := setProdShapedKeys(t)
	t.Setenv("PLATE_JWT_KEY_ACCOUNTS", "uri=uriaran,registry=reg_*")
	cfg, err := LoadEnv()
	if err != nil {
		t.Fatal(err)
	}
	st := newStubStore()
	h := stubService(t, st, cfg.Verifier).Router()
	put := func(tok string) (int, string) {
		rec := do(t, h, "PUT", "/v1/account", tok)
		return rec.Code, trimBody(rec)
	}

	// Refused before the store is ever touched.
	for _, c := range []struct {
		name string
		tok  string
		want int
	}{
		{"unbound kid with the scope", envToken(t, k.files, "files", "reg_t1", "accounts:provision"), http.StatusForbidden},
		{"legacy (unbound) with the scope", envToken(t, k.legacy, "", "reg_t1", "accounts:provision"), http.StatusForbidden},
		{"exact-bound kid with the scope", envToken(t, k.uri, "uri", "uriaran", "accounts:provision"), http.StatusForbidden},
		{"namespace kid without the scope", envToken(t, k.registry, "registry", "reg_t1", "assets:read", "assets:write"), http.StatusForbidden},
		{"namespace kid outside its namespace", envToken(t, k.registry, "registry", "uriaran", "accounts:provision"), http.StatusUnauthorized},
		{"no token", "", http.StatusUnauthorized},
	} {
		if code, body := put(c.tok); code != c.want {
			t.Errorf("%s: PUT /v1/account = %d %s, want %d", c.name, code, body, c.want)
		}
	}
	if st.provisionCalls != 0 {
		t.Fatalf("a refused provisioning reached the store %d time(s)", st.provisionCalls)
	}

	// The namespace issuer, with the scope: creates, then idempotent.
	tok := envToken(t, k.registry, "registry", "reg_t1", "accounts:provision")
	code, body := put(tok)
	if code != http.StatusCreated {
		t.Fatalf("first provisioning = %d %s, want 201", code, body)
	}
	var first plate.AccountProvisioning
	if err := json.Unmarshal([]byte(body), &first); err != nil {
		t.Fatal(err)
	}
	if !first.Created || first.Account.Id != "reg_t1" {
		t.Fatalf("first provisioning body = %+v", first)
	}
	code, body = put(tok)
	var again plate.AccountProvisioning
	_ = json.Unmarshal([]byte(body), &again)
	if code != http.StatusOK || again.Created || again.Account != first.Account {
		t.Fatalf("repeat provisioning = %d %+v, want 200 created:false and the same account", code, again)
	}
}
