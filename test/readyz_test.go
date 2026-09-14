package plate_test

// /readyz is REAL now (Tier 1 monitoring). These prove, against a real
// Postgres, the property the slice exists for: a worker that is dead, stuck,
// or never came up is VISIBLE from the API's readiness — as "degraded" (200),
// never as "down" — while a dependency the API itself needs (db, storage)
// failing is "down" (503). And that the body names WHICH check failed.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/service"
	"github.com/chuckyatsuk/plate/internal/storage"
	"github.com/chuckyatsuk/plate/internal/store"
)

// okStorage answers HEAD with "absent, no error" — a reachable bucket with
// valid credentials. Every other method is unused by readiness (nil-embedded).
type okStorage struct{ storage.Storage }

func (okStorage) Head(context.Context, string) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{Exists: false}, nil
}

// deadStorage answers HEAD with a transport/credential error.
type deadStorage struct{ storage.Storage }

func (deadStorage) Head(context.Context, string) (storage.ObjectInfo, error) {
	return storage.ObjectInfo{}, errors.New("dial tcp: connection refused")
}

// deadStore is a Store whose database is unreachable. Only the health methods
// are implemented; readiness must not touch anything else.
type deadStore struct{ store.Store }

func (deadStore) Ping(context.Context) error { return errors.New("failed to connect") }
func (deadStore) WorkerLiveness(context.Context) (store.WorkerLiveness, error) {
	return store.WorkerLiveness{}, errors.New("failed to connect")
}
func (deadStore) QueueLag(context.Context) (store.QueueLag, error) {
	return store.QueueLag{}, errors.New("failed to connect")
}

func readyz(t *testing.T, st store.Store, stor storage.Storage, hc service.HealthConfig) (int, plate.Health) {
	t.Helper()
	svc := service.New(service.Config{Store: st, Storage: stor, Health: hc})
	rec := httptest.NewRecorder()
	svc.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/readyz", nil))
	var body plate.Health
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("readyz body is not Health JSON: %v — %s", err, rec.Body.String())
	}
	if body.Checks == nil {
		t.Fatalf("readyz body carries no checks: %s", rec.Body.String())
	}
	return rec.Code, body
}

func resetHealthRows(t *testing.T, st *store.Postgres) {
	t.Helper()
	ctx := context.Background()
	for _, q := range []string{
		`DELETE FROM worker_heartbeats`,
		`DELETE FROM jobs WHERE account = $1`,
		`DELETE FROM assets WHERE account = $1`,
	} {
		if _, err := st.Pool().Exec(ctx, q, reconcileAccount); err != nil && q != `DELETE FROM worker_heartbeats` {
			t.Fatalf("reset: %s: %v", q, err)
		}
	}
	if _, err := st.Pool().Exec(ctx, `DELETE FROM worker_heartbeats`); err != nil {
		t.Fatalf("reset heartbeats: %v", err)
	}
}

func okDetail(c *plate.HealthCheck) (bool, string) {
	if c == nil {
		return false, "<absent>"
	}
	if c.Detail == nil {
		return c.Ok, ""
	}
	return c.Ok, *c.Detail
}

// No worker has ever beaten: the API can serve (db + storage fine) but the
// background side is missing → degraded, 200, and the worker check says why.
func TestReadyz_NoWorkerEver_IsDegradedNotDown(t *testing.T) {
	st := storeForTest(t)
	resetHealthRows(t, st)

	code, body := readyz(t, st, okStorage{}, service.HealthConfig{})
	if code != http.StatusOK || body.Status != plate.Degraded {
		t.Fatalf("no worker: want 200 degraded, got %d %s", code, body.Status)
	}
	if ok, d := okDetail(body.Checks.Worker); ok || d == "" {
		t.Errorf("worker check should fail with a reason, got ok=%v detail=%q", ok, d)
	}
	for name, c := range map[string]*plate.HealthCheck{"db": body.Checks.Db, "storage": body.Checks.Storage, "queue": body.Checks.Queue} {
		if ok, d := okDetail(c); !ok {
			t.Errorf("%s should be ok, got %q", name, d)
		}
	}
}

// A fresh heartbeat → ok. A stale one → degraded with "stale" in the detail.
func TestReadyz_WorkerHeartbeat_FreshOkStaleDegraded(t *testing.T) {
	st := storeForTest(t)
	resetHealthRows(t, st)
	ctx := context.Background()

	if err := st.UpsertWorkerHeartbeat(ctx, "machine-a", "img:1", nil); err != nil {
		t.Fatal(err)
	}
	code, body := readyz(t, st, okStorage{}, service.HealthConfig{WorkerStaleAfter: 2 * time.Minute})
	if code != http.StatusOK || body.Status != plate.Ok {
		t.Fatalf("fresh heartbeat: want 200 ok, got %d %s (%+v)", code, body.Status, *body.Checks.Worker)
	}

	// Age the beat past the threshold (simulating a worker that died 10m ago).
	if _, err := st.Pool().Exec(ctx, `UPDATE worker_heartbeats SET last_seen = now() - interval '10 minutes'`); err != nil {
		t.Fatal(err)
	}
	code, body = readyz(t, st, okStorage{}, service.HealthConfig{WorkerStaleAfter: 2 * time.Minute})
	if code != http.StatusOK || body.Status != plate.Degraded {
		t.Fatalf("stale heartbeat: want 200 degraded, got %d %s", code, body.Status)
	}
	if ok, d := okDetail(body.Checks.Worker); ok || d == "" {
		t.Errorf("stale worker check should fail with detail, got ok=%v %q", ok, d)
	}

	// A second, live worker makes the fleet healthy again ("at least one alive").
	if err := st.UpsertWorkerHeartbeat(ctx, "machine-b", "img:1", nil); err != nil {
		t.Fatal(err)
	}
	if code, body = readyz(t, st, okStorage{}, service.HealthConfig{WorkerStaleAfter: 2 * time.Minute}); body.Status != plate.Ok {
		t.Fatalf("second live worker: want ok, got %d %s", code, body.Status)
	}
}

// Sweep freshness rides on the heartbeat: the detail reports it, and a later
// beat with no sweep time does NOT erase an earlier sweep time (COALESCE).
func TestReadyz_HeartbeatKeepsLastSweep(t *testing.T) {
	st := storeForTest(t)
	resetHealthRows(t, st)
	ctx := context.Background()

	sweep := time.Now().Add(-3 * time.Minute)
	if err := st.UpsertWorkerHeartbeat(ctx, "machine-a", "img:1", &sweep); err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertWorkerHeartbeat(ctx, "machine-a", "img:1", nil); err != nil {
		t.Fatal(err)
	}
	wl, err := st.WorkerLiveness(ctx)
	if err != nil || !wl.Seen || wl.LastSweep == nil {
		t.Fatalf("last sweep lost after a nil-sweep beat: %+v err=%v", wl, err)
	}
	_, body := readyz(t, st, okStorage{}, service.HealthConfig{})
	if _, d := okDetail(body.Checks.Worker); d == "" || !contains(d, "last sweep") {
		t.Errorf("worker detail should report sweep freshness, got %q", d)
	}
}

// A queued job older than the lag threshold → degraded via the queue check,
// even with a live worker (alive-but-stuck is still an incident).
func TestReadyz_QueueLag_IsDegraded(t *testing.T) {
	st := storeForTest(t)
	resetHealthRows(t, st)
	ctx := context.Background()
	if err := st.UpsertWorkerHeartbeat(ctx, "machine-a", "img:1", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO assets (id, account, kind, vault_key, vault_checksum, vault_size_bytes)
		VALUES ('READYZASSET', $1, 'video', 'vault/x/READYZASSET', 'md5:0', 1)`, reconcileAccount); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(ctx, `
		INSERT INTO jobs (id, account, asset, intent, status, created)
		VALUES ('READYZJOB', $1, 'READYZASSET', 'detail', 'queued', now() - interval '20 minutes')`, reconcileAccount); err != nil {
		t.Fatal(err)
	}

	code, body := readyz(t, st, okStorage{}, service.HealthConfig{QueueLagMax: 10 * time.Minute})
	if code != http.StatusOK || body.Status != plate.Degraded {
		t.Fatalf("lagging queue: want 200 degraded, got %d %s", code, body.Status)
	}
	if ok, d := okDetail(body.Checks.Queue); ok || !contains(d, "1 queued") {
		t.Errorf("queue check should fail naming the backlog, got ok=%v %q", ok, d)
	}
	if ok, _ := okDetail(body.Checks.Worker); !ok {
		t.Errorf("worker is live; only the queue should fail")
	}

	// Same backlog, generous threshold → ok (lag is a threshold, not a count).
	if _, body = readyz(t, st, okStorage{}, service.HealthConfig{QueueLagMax: time.Hour}); body.Status != plate.Ok {
		t.Errorf("young backlog: want ok, got %s", body.Status)
	}
}

// Storage unreachable → DOWN (503): the API cannot presign/finalize/serve
// originals. This is the case Fly's check must act on.
func TestReadyz_StorageDown_Is503(t *testing.T) {
	st := storeForTest(t)
	resetHealthRows(t, st)
	if err := st.UpsertWorkerHeartbeat(context.Background(), "machine-a", "img:1", nil); err != nil {
		t.Fatal(err)
	}
	code, body := readyz(t, st, deadStorage{}, service.HealthConfig{})
	if code != http.StatusServiceUnavailable || body.Status != plate.Down {
		t.Fatalf("dead storage: want 503 down, got %d %s", code, body.Status)
	}
	if ok, d := okDetail(body.Checks.Storage); ok || !contains(d, "refused") {
		t.Errorf("storage check should carry the error, got ok=%v %q", ok, d)
	}
	if ok, _ := okDetail(body.Checks.Db); !ok {
		t.Errorf("db is fine; the body must not blame it")
	}
}

// Database unreachable → DOWN (503), and the worker/queue checks report their
// own query failures rather than crashing the probe.
func TestReadyz_DatabaseDown_Is503(t *testing.T) {
	code, body := readyz(t, deadStore{}, okStorage{}, service.HealthConfig{})
	if code != http.StatusServiceUnavailable || body.Status != plate.Down {
		t.Fatalf("dead db: want 503 down, got %d %s", code, body.Status)
	}
	if ok, _ := okDetail(body.Checks.Db); ok {
		t.Errorf("db check should fail")
	}
	if ok, _ := okDetail(body.Checks.Storage); !ok {
		t.Errorf("storage is fine; the body must not blame it")
	}
}

// PLATE_READYZ_CHECKS narrows the probe without a deploy: with only db
// enabled, a missing worker is not even consulted.
func TestReadyz_ChecksAllowlist(t *testing.T) {
	st := storeForTest(t)
	resetHealthRows(t, st)
	code, body := readyz(t, st, deadStorage{}, service.HealthConfig{Checks: []string{"db"}})
	if code != http.StatusOK || body.Status != plate.Ok {
		t.Fatalf("db-only allowlist: want 200 ok, got %d %s", code, body.Status)
	}
	if body.Checks.Storage != nil || body.Checks.Worker != nil || body.Checks.Queue != nil {
		t.Errorf("disabled checks must be absent from the body: %+v", *body.Checks)
	}
	if ok, _ := okDetail(body.Checks.Db); !ok {
		t.Errorf("db should be ok")
	}
}

// A read-only deployment (no storage configured) is not "down" — write handlers
// 501 honestly; readiness says so in the detail.
func TestReadyz_NoStorageConfigured_IsNotDown(t *testing.T) {
	st := storeForTest(t)
	resetHealthRows(t, st)
	if err := st.UpsertWorkerHeartbeat(context.Background(), "machine-a", "img:1", nil); err != nil {
		t.Fatal(err)
	}
	code, body := readyz(t, st, nil, service.HealthConfig{})
	if code != http.StatusOK || body.Status != plate.Ok {
		t.Fatalf("nil storage: want 200 ok, got %d %s", code, body.Status)
	}
	if ok, d := okDetail(body.Checks.Storage); !ok || !contains(d, "not configured") {
		t.Errorf("storage check should be ok with a 'not configured' detail, got ok=%v %q", ok, d)
	}
}

// /healthz stays a pure liveness ping: no checks, always ok — it must keep
// answering even when readiness is down, or Fly would restart a healthy process.
func TestHealthz_IsLivenessOnly(t *testing.T) {
	svc := service.New(service.Config{Store: deadStore{}, Storage: deadStorage{}})
	rec := httptest.NewRecorder()
	svc.Router().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/healthz", nil))
	var body plate.Health
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusOK || body.Status != plate.Ok || body.Checks != nil {
		t.Fatalf("healthz must be 200 ok with no checks even when everything is down: %d %s", rec.Code, rec.Body.String())
	}
}

func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
