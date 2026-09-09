package plate_test

// This file WIRES the real read-path service into the isolation conformance test
// (test/account_isolation_test.go), turning its two pending-skips green — the
// acceptance bar for Phase 1 (spec §8).
//
// It does the thing the spec insists on: the isolation guarantee is proven
// against REAL SQL, on an EPHEMERAL Postgres the test starts and tears down
// (spec §7, Q2) — a throwaway postgres:16-alpine container, migrated with the
// SAME migrations the shipped compose Postgres runs, seeded with accounts A and
// B, then hit with REAL HTTP requests carrying a REAL A-token. No Atlas, no
// shared DB, no secrets. If Docker is absent the service is simply not
// registered and the conformance test skips-pending (fails toward "not yet
// proven"), exactly like the container-backed imgproxy tests already do.
//
// The adapter implements support.AccountScopedService by issuing real requests
// through the service's router via httptest — so the assertions (denied, and B's
// data never in the body) check the real response of the real handler stack, not
// a recorded call.

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/auth"
	"github.com/chuckyatsuk/plate/internal/probe"
	"github.com/chuckyatsuk/plate/internal/service"
	"github.com/chuckyatsuk/plate/internal/storage"
	"github.com/chuckyatsuk/plate/internal/store"
	"github.com/chuckyatsuk/plate/test/harness"
	"github.com/chuckyatsuk/plate/test/support"

	"github.com/golang-jwt/jwt/v5"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestMain stands up the ephemeral Postgres, migrates and seeds it, wires the
// real service, and registers it for the conformance test. When Docker is
// unavailable it registers nothing, so the conformance test skips-pending.
func TestMain(m *testing.M) {
	code := runWithService(m)
	os.Exit(code)
}

func runWithService(m *testing.M) int {
	if !harness.DockerReachable() {
		// No Docker: leave the service unregistered → conformance skips-pending.
		fmt.Fprintln(os.Stderr, "plate_test: no Docker daemon; isolation conformance will skip-pending (needs an ephemeral Postgres).")
		return m.Run()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	pg, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("plate"),
		tcpostgres.WithUsername("plate"),
		tcpostgres.WithPassword("plate"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plate_test: starting ephemeral Postgres failed: %v\n", err)
		return m.Run() // skip-pending rather than hard-fail the whole suite
	}
	defer func() { _ = pg.Terminate(context.Background()) }()

	connString, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Fprintf(os.Stderr, "plate_test: connection string: %v\n", err)
		return m.Run()
	}

	// Run the REAL migrations — the same ones the compose Postgres uses. No
	// hand-written test schema, so the two cannot drift (spec §6).
	if err := store.Migrate(ctx, connString); err != nil {
		fmt.Fprintf(os.Stderr, "plate_test: migrate: %v\n", err)
		return m.Run()
	}

	st, err := store.Open(ctx, connString)
	if err != nil {
		fmt.Fprintf(os.Stderr, "plate_test: open store: %v\n", err)
		return m.Run()
	}
	defer st.Close()

	if err := seedAccountsAndB(ctx, st); err != nil {
		fmt.Fprintf(os.Stderr, "plate_test: seed: %v\n", err)
		return m.Run()
	}

	// A real verifier + issuer keypair. The account travels only in the token.
	pub, priv := auth.TestKeyPair()
	verf := auth.NewVerifier(pub, "", "") // issuer/aud checks off in test

	// A real storage backend (MinIO) + prober so the WRITE endpoints are exercised
	// under isolation for real (condition C3: isolation grows with the write path).
	// The cross-account write assertions fire on the account-scoped DB lookups
	// (GetUpload/AssetOwnedBy) BEFORE any storage call, but storage must be present
	// for the handler to reach that check rather than 501.
	stor, prober, storErr := startStorageForWiring(ctx)
	if storErr != nil {
		fmt.Fprintf(os.Stderr, "plate_test: storage for wiring: %v\n", storErr)
		return m.Run() // skip-pending rather than fail the whole suite
	}

	svc := service.New(service.Config{
		Store:    st,
		Verifier: verf,
		Storage:  stor,
		Prober:   prober,
		URLs: service.URLBuilder{
			ImageCDNBase: "https://cdn.example",
			R2PublicBase: "https://r2.example",
			DownloadBase: "https://plate.example",
		},
	})

	support.SetAccountScopedService(&realService{
		handler: svc.Router(),
		priv:    priv,
	})

	return m.Run()
}

// seedAccountsAndB inserts accounts A and B and B's resources, tagged with the
// sentinels the conformance test looks for, so any leak of B's data to A is
// caught. Seeding goes straight to the pool — the service NEVER bypasses its
// account-scoped methods; the test only sets up the world.
func seedAccountsAndB(ctx context.Context, st *store.Postgres) error {
	pool := st.Pool()
	// Accounts. (Ids match the conformance test's accountA/accountB.)
	for _, acct := range []string{"acct-a", "acct-b"} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO accounts (id) VALUES ($1) ON CONFLICT DO NOTHING`, acct); err != nil {
			return err
		}
	}
	// B's asset — its key is the sentinel the leak check hunts for.
	if _, err := pool.Exec(ctx, `
		INSERT INTO assets (id, account, kind, vault_key, vault_checksum, vault_size_bytes)
		VALUES ($1, 'acct-b', 'image', $2, 'sha256:bbbb', 1024)`,
		"01BBBBBBBBBBBBBBBBBBBBBBBB", "acct-b/01BBBBBBBBBBBBBBBBBBBBBBBB"); err != nil {
		return err
	}
	// A's OWN asset — so the enumeration assertion (listAssets) can verify BOTH
	// directions: B absent AND A present. Without this, "no B data" is a vacuous
	// pass on an empty list.
	if _, err := pool.Exec(ctx, `
		INSERT INTO assets (id, account, kind, vault_key, vault_checksum, vault_size_bytes)
		VALUES ($1, 'acct-a', 'image', $2, 'sha256:aaaa', 2048)`,
		"01AAAAAAAAAAAAAAAAAAAAAAAA", "acct-a/01AAAAAAAAAAAAAAAAAAAAAAAA"); err != nil {
		return err
	}
	// B's job.
	if _, err := pool.Exec(ctx, `
		INSERT INTO jobs (id, account, asset, intent, status)
		VALUES ($1, 'acct-b', $2, 'detail', 'queued')`,
		"01BBBBBBBBBBBBBBBBBBBBJOB0", "01BBBBBBBBBBBBBBBBBBBBBBBB"); err != nil {
		return err
	}
	// B's grant over B's asset.
	if _, err := pool.Exec(ctx, `
		INSERT INTO grants (id, account, assets, expires)
		VALUES ($1, 'acct-b', $2, now() + interval '1 day')`,
		"01BBBBBBBBBBBBBBBBBBBGRANT", []string{"01BBBBBBBBBBBBBBBBBBBBBBBB"}); err != nil {
		return err
	}
	return nil
}

// realService adapts the running HTTP service to support.AccountScopedService by
// issuing real requests through its router.
type realService struct {
	handler http.Handler
	priv    ed25519.PrivateKey
}

// tokenFor mints a real service JWT whose ONLY carrier of the account is the
// `account` claim (spec Q3.A). The caller's scopes are included so a denial
// cannot pass for the wrong reason (missing scope).
func (rs *realService) tokenFor(a support.Actor) string {
	scopes := make([]string, 0, len(a.Scopes))
	for _, s := range a.Scopes {
		scopes = append(scopes, string(s))
	}
	tok, err := auth.Sign(rs.priv, auth.Claims{
		Account:          string(a.Account),
		Scope:            scopes,
		RegisteredClaims: authRegisteredClaims(),
	})
	if err != nil {
		panic(err)
	}
	return tok
}

// do issues one request through the real router and captures the response.
func (rs *realService) do(method, path, token, body string) support.ConformanceResponse {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	rs.handler.ServeHTTP(rec, req)
	return support.ConformanceResponse{Status: rec.Code, Body: rec.Body.Bytes()}
}

// CallCrossAccount performs the named endpoint AS caller AGAINST the (B-owned)
// target, returning the real response. Every path uses the B-owned resource id;
// the account is only ever in the token.
func (rs *realService) CallCrossAccount(ep support.EndpointID, caller support.Actor, target support.Resource) support.ConformanceResponse {
	tok := rs.tokenFor(caller)
	switch ep {
	case support.EpResolveDeliveryUrl:
		return rs.do("GET", "/v1/assets/"+target.ID+"/url?intent=lightbox", tok, "")
	case support.EpGetAsset:
		return rs.do("GET", "/v1/assets/"+target.ID, tok, "")
	case support.EpDeleteAsset:
		return rs.do("DELETE", "/v1/assets/"+target.ID, tok, "")
	case support.EpListAssets:
		// listAssets has no target id; it must return ONLY the caller's assets and
		// never B's. A leak here would be B's data appearing in A's list.
		return rs.do("GET", "/v1/assets", tok, "")
	case support.EpRequestRendition:
		return rs.do("POST", "/v1/assets/"+target.ID+"/renditions", tok, `{"intent":"lightbox"}`)
	case support.EpGetJob:
		return rs.do("GET", "/v1/jobs/"+target.ID, tok, "")
	case support.EpFinalizeUpload:
		return rs.do("POST", "/v1/uploads/"+target.ID+"/finalize", tok, `{"checksum":"sha256:x"}`)
	case support.EpCreateGrant:
		// A grant over B's asset must be refused wholesale.
		return rs.do("POST", "/v1/grants", tok,
			`{"assets":["`+target.ID+`"],"expires":"`+farFuture()+`"}`)
	case support.EpGetGrant:
		return rs.do("GET", "/v1/grants/"+target.ID, tok, "")
	case support.EpRevokeGrant:
		return rs.do("DELETE", "/v1/grants/"+target.ID, tok, "")
	default:
		return support.ConformanceResponse{Status: http.StatusInternalServerError, Body: []byte("unmapped endpoint " + string(ep))}
	}
}

// MintUploadKey performs createUpload as caller and returns the storage key the
// minted upload is bound to. The requestedAccountHint is deliberately passed to
// prove it is IGNORED — the key must carry the caller's account, never the hint.
// UploadRequest has no account field, so the hint cannot even be expressed in the
// body; we still exercise the path and read the key back out of the ticket URL.
func (rs *realService) MintUploadKey(caller support.Actor, requestedAccountHint string) (string, support.ConformanceResponse) {
	tok := rs.tokenFor(caller)
	// The body carries no account (the contract forbids it); the hint is a
	// smuggling attempt that has nowhere to go — which is the point.
	resp := rs.do("POST", "/v1/uploads", tok, `{"content_type":"image/jpeg","size_bytes":1024}`)
	key := keyFromTicket(resp.Body)
	return key, resp
}

// ── shared ephemeral Postgres for direct store-level tests ──────────────────

const reconcileAccount = "acct-reconcile"

// sharedStore is an ephemeral Postgres store, started once, that direct
// store-level tests (e.g. the reconciliation test) use via storeForTest. It is
// separate from the isolation service's store so those tests don't interfere.
var (
	sharedStore    *store.Postgres
	sharedStoreErr error
	sharedStoreCtx = context.Background()
	storeOnce      sync.Once
)

// freshStore starts a BRAND-NEW ephemeral Postgres (container + migrations + the
// reconcile account), fully isolated from other tests. Use it where a test needs
// exclusive control of table contents — e.g. the queue tests, whose "nothing
// else is claimable" assertions depend on the queue holding only their own jobs.
// Terminated when the test finishes.
func freshStore(t *testing.T) *store.Postgres {
	t.Helper()
	harness.RequireDocker(t)
	ctx := context.Background()
	pg, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("plate"),
		tcpostgres.WithUsername("plate"),
		tcpostgres.WithPassword("plate"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("freshStore: start postgres: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(context.Background()) })
	conn, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("freshStore: conn string: %v", err)
	}
	if err := store.Migrate(ctx, conn); err != nil {
		t.Fatalf("freshStore: migrate: %v", err)
	}
	st, err := store.Open(ctx, conn)
	if err != nil {
		t.Fatalf("freshStore: open: %v", err)
	}
	t.Cleanup(st.Close)
	if _, err := st.Pool().Exec(ctx,
		`INSERT INTO accounts (id) VALUES ($1) ON CONFLICT DO NOTHING`, reconcileAccount); err != nil {
		t.Fatalf("freshStore: seed account: %v", err)
	}
	return st
}

// storeForTest returns the shared ephemeral store, starting it (Postgres
// container + migrations + a seeded account) on first use. Skips the test if
// Docker is unavailable — the same visible behavior as the other container tests.
func storeForTest(t *testing.T) *store.Postgres {
	t.Helper()
	harness.RequireDocker(t)
	storeOnce.Do(func() {
		pg, err := tcpostgres.Run(sharedStoreCtx, "postgres:16-alpine",
			tcpostgres.WithDatabase("plate"),
			tcpostgres.WithUsername("plate"),
			tcpostgres.WithPassword("plate"),
			tcpostgres.BasicWaitStrategies(),
		)
		if err != nil {
			sharedStoreErr = err
			return
		}
		conn, err := pg.ConnectionString(sharedStoreCtx, "sslmode=disable")
		if err != nil {
			sharedStoreErr = err
			return
		}
		if err := store.Migrate(sharedStoreCtx, conn); err != nil {
			sharedStoreErr = err
			return
		}
		st, err := store.Open(sharedStoreCtx, conn)
		if err != nil {
			sharedStoreErr = err
			return
		}
		if _, err := st.Pool().Exec(sharedStoreCtx,
			`INSERT INTO accounts (id) VALUES ($1) ON CONFLICT DO NOTHING`, reconcileAccount); err != nil {
			sharedStoreErr = err
			return
		}
		sharedStore = st
	})
	if sharedStoreErr != nil {
		t.Fatalf("shared store: %v", sharedStoreErr)
	}
	return sharedStore
}

// startStorageForWiring stands up a MinIO container and a prober for the isolation
// wiring. It is the no-*testing.T analog of harness.StartMinIO (TestMain has no T).
// The container is terminated when the process exits (tests own the lifetime).
func startStorageForWiring(ctx context.Context) (*storage.S3, *probe.Prober, error) {
	const user, pass, bucket = "plate", "plate-secret", "plate-isolation"
	c, err := tcminio.Run(ctx, "minio/minio:latest",
		tcminio.WithUsername(user), tcminio.WithPassword(pass))
	if err != nil {
		return nil, nil, err
	}
	// Not terminated explicitly: the container is reaped by testcontainers' ryuk
	// when the test process exits. (TestMain has no t.Cleanup.)
	endpoint, err := c.ConnectionString(ctx)
	if err != nil {
		return nil, nil, err
	}
	st, err := storage.New(ctx, storage.Config{
		Endpoint:     "http://" + endpoint,
		Region:       "us-east-1",
		AccessKey:    user,
		SecretKey:    pass,
		Bucket:       bucket,
		UsePathStyle: true,
	})
	if err != nil {
		return nil, nil, err
	}
	if err := st.EnsureBucket(ctx); err != nil {
		return nil, nil, err
	}
	return st, probe.New(""), nil
}

// authRegisteredClaims builds a valid, short-lived set of registered claims for
// a test token (a real expiry so the verifier's exp check is exercised).
func authRegisteredClaims() jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		Subject:   "files",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
}

// farFuture is an RFC3339 timestamp a day out, for grant expiry in request bodies.
func farFuture() string { return time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339) }

// keyFromTicket extracts the {account}/{asset-id} key from the ticket's real
// presigned PUT URL. A path-style presigned URL is
// `http://host:port/{bucket}/{account}/{asset-id}?X-Amz-...`, so the key is the
// last TWO segments of the URL PATH (ignoring the query). JSON-decoding the
// ticket first avoids mishandling escaped characters in the signed query.
func keyFromTicket(body []byte) string {
	var ticket struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &ticket); err != nil || ticket.URL == "" {
		return ""
	}
	u, err := neturl.Parse(ticket.URL)
	if err != nil {
		return ""
	}
	segs := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(segs) < 2 {
		return ""
	}
	// key = last two path segments: {account}/{asset-id}. The bucket (and any
	// prefix) precede them and are dropped.
	return segs[len(segs)-2] + "/" + segs[len(segs)-1]
}
