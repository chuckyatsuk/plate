package plate_test

// Account provisioning is out-of-band (spec Q2; designer 2026-09-10): an account
// must be created before its first upload (uploads.account has an FK). This proves
// the two halves of that contract:
//   - an upload for an UNPROVISIONED account fails LEGIBLY (403 unknown_account),
//     never a bare 500 — the "first upload against a missing account" trap;
//   - after CreateAccount (what `plate accounts create` calls), the SAME upload
//     succeeds.

import (
	"context"
	"encoding/json"
	"testing"
)

func TestE2E_UploadUnprovisionedAccount_FailsLegibly(t *testing.T) {
	e := newE2E(t, 720)

	// A token for an account that was never seeded.
	ghost := "ghost-acct-unprovisioned"
	tok := signToken(t, e.priv, ghost, "assets:write,assets:read")

	body := mustJSON(map[string]any{"content_type": "image/png", "size_bytes": 1024})
	req := reqWithToken("POST", "/v1/uploads", body, tok)
	rec := newRecorder()
	e.handler.ServeHTTP(rec, req)

	if rec.Code != 403 {
		t.Fatalf("upload for an unprovisioned account must be a legible 403, never 500; got %d: %s", rec.Code, rec.Body.String())
	}
	var errBody struct{ Code string }
	_ = json.Unmarshal(rec.Body.Bytes(), &errBody)
	if errBody.Code != "unknown_account" {
		t.Fatalf("expected code=unknown_account; got %q (body %s)", errBody.Code, rec.Body.String())
	}

	// Provision it (what `plate accounts create` does) — then the same upload works.
	if err := e.st.CreateAccount(context.Background(), ghost, "", ""); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	rec2 := newRecorder()
	e.handler.ServeHTTP(rec2, reqWithToken("POST", "/v1/uploads", body, tok))
	if rec2.Code != 201 {
		t.Fatalf("after provisioning, upload must succeed (201); got %d: %s", rec2.Code, rec2.Body.String())
	}
}

// CreateAccount is idempotent (ON CONFLICT DO UPDATE) — re-provisioning must not error.
func TestE2E_CreateAccount_Idempotent(t *testing.T) {
	e := newE2E(t, 720)
	ctx := context.Background()
	id := "idem-acct"
	if err := e.st.CreateAccount(ctx, id, "b1", "p1"); err != nil {
		t.Fatalf("first CreateAccount: %v", err)
	}
	if err := e.st.CreateAccount(ctx, id, "b2", "p2"); err != nil {
		t.Fatalf("re-provisioning the same account must not error; got %v", err)
	}
}
