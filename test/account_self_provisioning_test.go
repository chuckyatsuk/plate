package plate_test

// PUT /v1/account — self-provisioning by a NAMESPACE issuer (tenancy design
// option A, rulings T2/T3), against real Postgres. The account is the token
// claim; the verb needs the accounts:provision scope AND a prefix-bound key; it
// is INSERT … ON CONFLICT DO NOTHING, so a repeat never re-configures anything.
// On the pre-batch code the route does not exist (every call below 404s/405s).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

type provisioning struct {
	Account struct {
		ID      string    `json:"id"`
		Created time.Time `json:"created"`
	} `json:"account"`
	Created bool `json:"created"`
}

func (e *e2e) provision(token string) (int, provisioning, string) {
	e.t.Helper()
	code, body := e.as(token, "PUT", "/v1/account", nil)
	var p provisioning
	if code == http.StatusOK || code == http.StatusCreated {
		if err := json.Unmarshal([]byte(body), &p); err != nil {
			e.t.Fatalf("decode provisioning: %v (%s)", err, body)
		}
	}
	return code, p, body
}

func (e *e2e) accountRow(id string) (exists bool, bucket, prefix string, created time.Time) {
	e.t.Helper()
	err := e.st.Pool().QueryRow(context.Background(),
		`SELECT storage_bucket, storage_prefix, created FROM accounts WHERE id = $1`, id).Scan(&bucket, &prefix, &created)
	if err != nil {
		return false, "", "", time.Time{}
	}
	return true, bucket, prefix, created
}

func TestProvisionAccount_NamespaceIssuerCreatesIdempotently(t *testing.T) {
	uri, registry, files, verf := boundKeysEnv(t)
	e := newE2EWithVerifier(t, 720, verf)
	const tenant = "reg_prov1"
	uploadBody := mustJSON(map[string]any{"content_type": "image/png", "size_bytes": 1024})
	tenantTok := registry.token(t, tenant, "accounts:provision", "assets:write", "assets:read")

	// Before provisioning, the tenant's upload is still the legible refusal —
	// a bound key does NOT auto-create accounts.
	if code, body := e.as(tenantTok, "POST", "/v1/uploads", uploadBody); code != http.StatusForbidden || !strings.Contains(body, "unknown_account") {
		t.Fatalf("upload for an unprovisioned account = %d %s, want 403 unknown_account", code, body)
	}

	// Refusals: none of these may create the row.
	for _, c := range []struct {
		name string
		tok  string
		want int
	}{
		{"unbound kid with the scope", files.token(t, tenant, "accounts:provision"), http.StatusForbidden},
		{"exact-bound kid with the scope", uri.token(t, "uri-e2e", "accounts:provision"), http.StatusForbidden},
		{"namespace kid without the scope", registry.token(t, tenant, "assets:write", "assets:read"), http.StatusForbidden},
		{"namespace kid outside its namespace", registry.token(t, "uri-e2e", "accounts:provision"), http.StatusUnauthorized},
	} {
		if code, _, body := e.provision(c.tok); code != c.want {
			t.Errorf("%s: PUT /v1/account = %d %s, want %d", c.name, code, body, c.want)
		}
	}
	for _, a := range []string{tenant, "uri-e2e"} {
		if exists, _, _, _ := e.accountRow(a); exists {
			t.Fatalf("a refused provisioning created account %q", a)
		}
	}

	// The namespace issuer creates it.
	code, first, body := e.provision(tenantTok)
	if code != http.StatusCreated || !first.Created || first.Account.ID != tenant {
		t.Fatalf("first provisioning = %d %s, want 201 created:true for %s", code, body, tenant)
	}
	exists, _, _, created := e.accountRow(tenant)
	if !exists || !created.Equal(first.Account.Created) {
		t.Fatalf("row after provisioning: exists=%v created=%v, response said %v", exists, created, first.Account.Created)
	}

	// Repeat: 200, created:false, nothing changed.
	code, again, body := e.provision(tenantTok)
	if code != http.StatusOK || again.Created || again.Account.ID != tenant || !again.Account.Created.Equal(first.Account.Created) {
		t.Fatalf("repeat provisioning = %d %s, want 200 created:false with the original row", code, body)
	}

	// Now the same upload succeeds.
	if code, body := e.as(tenantTok, "POST", "/v1/uploads", uploadBody); code != http.StatusCreated {
		t.Fatalf("upload after provisioning = %d %s, want 201", code, body)
	}
}

// Provisioning NEVER re-configures an existing account — unlike the operator
// CLI's upsert, which overwrites bucket/prefix.
func TestProvisionAccount_NeverOverwritesOperatorConfig(t *testing.T) {
	_, registry, _, verf := boundKeysEnv(t)
	e := newE2EWithVerifier(t, 720, verf)
	const tenant = "reg_operator_set"
	if err := e.st.CreateAccount(context.Background(), tenant, "custom-bucket", "custom/prefix"); err != nil {
		t.Fatal(err)
	}
	_, _, _, before := e.accountRow(tenant)
	code, p, body := e.provision(registry.token(t, tenant, "accounts:provision"))
	if code != http.StatusOK || p.Created {
		t.Fatalf("provisioning an existing account = %d %s, want 200 created:false", code, body)
	}
	_, bucket, prefix, after := e.accountRow(tenant)
	if bucket != "custom-bucket" || prefix != "custom/prefix" || !after.Equal(before) {
		t.Fatalf("provisioning changed the operator's row: bucket=%q prefix=%q created %v→%v", bucket, prefix, before, after)
	}
}

// Two provisioners racing on a new tenant (the outbox worker and ensure-on-use):
// both succeed, exactly one reports created:true.
func TestProvisionAccount_ConcurrentFirstCalls(t *testing.T) {
	_, registry, _, verf := boundKeysEnv(t)
	e := newE2EWithVerifier(t, 720, verf)
	tok := registry.token(t, "reg_race", "accounts:provision")
	const n = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		created int
		bad     []int
	)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := newRecorder()
			e.handler.ServeHTTP(rec, reqWithToken("PUT", "/v1/account", nil, tok))
			var p provisioning
			_ = json.Unmarshal(rec.Body.Bytes(), &p)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case rec.Code == http.StatusCreated && p.Created:
				created++
			case rec.Code == http.StatusOK && !p.Created:
			default:
				bad = append(bad, rec.Code)
			}
		}()
	}
	wg.Wait()
	if len(bad) > 0 || created != 1 {
		t.Fatalf("%d concurrent provisionings: %d reported created, unexpected statuses %v; want exactly 1 created and no errors", n, created, bad)
	}
}
