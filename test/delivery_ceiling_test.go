package plate_test

// The incident the whole suite is named for, proven END TO END in the REAL
// service (review ruling 1): a finalized A/V asset over the detail duration
// ceiling resolves `detail` to delivery:null + exceeded_duration_ceiling — the
// §4.3 honest refusal — through the actual HTTP handler + worker + Postgres +
// storage, not the support stub.
//
// Before this, av_duration_ceiling_test only exercised the support ceiling stub;
// "refuses at delivery" was aspirational in the real service. This closes that.
//
// It also proves the happy path: a SHORT A/V asset transcodes and detail resolves
// to a real URL — so the ceiling test can't pass by refusing everything, and the
// worker-written-rendition → resolveDeliveryUrl path (untested until now) runs.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/probe"
	"github.com/chuckyatsuk/plate/internal/service"
	"github.com/chuckyatsuk/plate/internal/store"
	"github.com/chuckyatsuk/plate/internal/worker"
	"github.com/chuckyatsuk/plate/test/harness"
)

// e2e is a full local Plate: real store (ephemeral PG), real storage (MinIO),
// real HTTP handler, and a real worker driven synchronously.
type e2e struct {
	t       *testing.T
	st      *store.Postgres
	stor    *harness.MinIO
	handler http.Handler
	worker  *worker.Worker
	token   string
	account string
}

func newE2E(t *testing.T, detailCeilingS float64) *e2e {
	t.Helper()
	harness.RequireDocker(t)
	harness.RequireFFmpeg(t)
	ctx := context.Background()

	st := freshStore(t) // ephemeral PG + reconcileAccount seeded
	acct := "e2e-acct"
	if _, err := st.Pool().Exec(ctx, `INSERT INTO accounts (id) VALUES ($1) ON CONFLICT DO NOTHING`, acct); err != nil {
		t.Fatalf("seed account: %v", err)
	}
	m := harness.StartMinIO(t, "e2e")

	pub, priv := ed25519Pair(t)
	verf := newVerifier(t, pub)
	svc := service.New(service.Config{
		Store:    st,
		Verifier: verf,
		Storage:  m.Storage,
		Prober:   probe.New(""),
		URLs: service.URLBuilder{
			ImageCDNBase: "https://cdn.example",
			// Point the A/V public base at the REAL MinIO bucket URL, so a resolved
			// detail URL is genuinely fetchable and the "real bytes" assertion means
			// something. {endpoint}/{bucket} + /{renditionKey} = the object URL.
			R2PublicBase: m.Endpoint + "/" + m.Bucket,
			DownloadBase: "https://plate.example",
		},
	})
	w := worker.New(worker.Config{
		Store:              st,
		Storage:            m.Storage,
		Transcoder:         worker.NewFFmpegTranscoder("", "ultrafast", 0),
		Prober:             probe.New(""),
		ScratchDir:         t.TempDir(),
		DetailMaxDurationS: detailCeilingS,
	})

	return &e2e{
		t: t, st: st, stor: m, handler: svc.Router(), worker: w,
		token:   signToken(t, priv, acct, "assets:read,assets:write,renditions:generate,grants:manage"),
		account: acct,
	}
}

// uploadAndFinalize runs createUpload → PUT → finalize for a local file, returning
// the asset id. Mirrors the browser broker flow (Plate never streams the bytes).
func (e *e2e) uploadAndFinalize(path, contentType string) string {
	return e.uploadAndFinalizeWithChecksum(path, contentType, "md5:unverified-in-test")
}

// uploadAndFinalizeWithChecksum is uploadAndFinalize with an explicit finalize
// checksum claim (so the checksum-verification tests can pass a real md5:…).
func (e *e2e) uploadAndFinalizeWithChecksum(path, contentType, checksum string) string {
	e.t.Helper()
	data, err := readFile(path)
	if err != nil {
		e.t.Fatal(err)
	}

	// createUpload
	body := mustJSON(map[string]any{"content_type": contentType, "size_bytes": len(data)})
	resp := e.req("POST", "/v1/uploads", body)
	if resp.Code != 201 {
		e.t.Fatalf("createUpload: HTTP %d: %s", resp.Code, resp.Body.String())
	}
	var ticket struct {
		UploadID string `json:"upload_id"`
		URL      string `json:"url"`
	}
	mustDecode(e.t, resp.Body.Bytes(), &ticket)

	// PUT the bytes straight to MinIO (rewrite the internal host for the test host).
	putURL := rewriteHost(ticket.URL, e.stor.Endpoint)
	putReq, _ := http.NewRequest("PUT", putURL, bytes.NewReader(data))
	putReq.Header.Set("Content-Type", contentType)
	putReq.ContentLength = int64(len(data))
	// The signed host must match what was signed; StartMinIO's storage client used
	// the same endpoint, so no host header override is needed here.
	pr, err := http.DefaultClient.Do(putReq)
	if err != nil {
		e.t.Fatalf("PUT: %v", err)
	}
	io.Copy(io.Discard, pr.Body)
	pr.Body.Close()
	if pr.StatusCode < 200 || pr.StatusCode >= 300 {
		e.t.Fatalf("PUT to storage: HTTP %d", pr.StatusCode)
	}

	// finalize
	fresp := e.req("POST", "/v1/uploads/"+ticket.UploadID+"/finalize", mustJSON(map[string]any{"checksum": checksum}))
	if fresp.Code != 201 {
		e.t.Fatalf("finalize: HTTP %d: %s", fresp.Code, fresp.Body.String())
	}
	return ticket.UploadID
}

// drainWorker processes jobs one at a time until the queue is empty.
func (e *e2e) drainWorker() {
	e.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for {
		err := e.worker.RunOnceForTest(ctx)
		if err == store.ErrNoJob {
			return
		}
		if err != nil {
			e.t.Fatalf("worker run-once: %v", err)
		}
	}
}

func (e *e2e) resolve(assetID, intent string) plateDeliveryResolution {
	e.t.Helper()
	resp := e.req("GET", "/v1/assets/"+assetID+"/url?intent="+intent, nil)
	if resp.Code != 200 {
		e.t.Fatalf("resolve %s: HTTP %d: %s", intent, resp.Code, resp.Body.String())
	}
	var out plateDeliveryResolution
	mustDecode(e.t, resp.Body.Bytes(), &out)
	return out
}

func (e *e2e) req(method, path string, body []byte) *httptest.ResponseRecorder {
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Authorization", "Bearer "+e.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

type plateDeliveryResolution struct {
	Intent   string `json:"intent"`
	Delivery *struct {
		URL  string `json:"url"`
		Mode string `json:"mode"`
	} `json:"delivery"`
	Reason *string `json:"reason"`
}

func TestE2E_DetailOverCeiling_RefusesAtDelivery(t *testing.T) {
	const ceiling = 5.0 // 5s ceiling so a cheap ~8s clip is "over"
	e := newE2E(t, ceiling)
	dir := t.TempDir()

	// A real 8-second A/V source — over the 5s ceiling.
	src := harness.SynthVideo(t, filepath.Join(dir, "long.mp4"), harness.Seconds(8), true)
	assetID := e.uploadAndFinalize(src, "video/mp4")

	// Worker probes + hits the ceiling → writes a failed detail rendition.
	e.drainWorker()

	res := e.resolve(assetID, "detail")
	if res.Delivery != nil {
		t.Fatalf("detail over ceiling should refuse; got a delivery URL: %+v", res.Delivery)
	}
	if res.Reason == nil || *res.Reason != "exceeded_duration_ceiling" {
		t.Fatalf("expected reason exceeded_duration_ceiling; got %v", res.Reason)
	}
}

func TestE2E_DetailUnderCeiling_ResolvesToURL(t *testing.T) {
	const ceiling = 720.0
	e := newE2E(t, ceiling)
	dir := t.TempDir()

	src := harness.SynthVideo(t, filepath.Join(dir, "short.mp4"), harness.Seconds(3), true)
	assetID := e.uploadAndFinalize(src, "video/mp4")
	e.drainWorker()

	res := e.resolve(assetID, "detail")
	if res.Delivery == nil {
		t.Fatalf("detail under ceiling should resolve to a URL; got refusal reason %v", res.Reason)
	}
	if res.Delivery.URL == "" {
		t.Fatal("resolved detail has empty URL")
	}

	// The resolved URL must point at REAL BYTES at the exact key the worker wrote —
	// not just be non-empty. This is what the deployed smoke caught that the earlier
	// test missed: a ready rendition whose URL key did NOT match the worker's key,
	// plus a silent zero-byte Put. Derive the object key from the resolved URL and
	// confirm, via the storage client, that a non-empty object exists there.
	key := keyFromPublicURL(res.Delivery.URL, e.stor.Bucket)
	info, err := e.stor.Storage.Head(context.Background(), key)
	if err != nil || !info.Exists {
		t.Fatalf("resolved detail URL points at key %q, but no object exists there (err=%v) — delivery key does not match the worker's write", key, err)
	}
	if info.Size == 0 {
		t.Fatalf("rendition object at %q is ZERO bytes — a silent empty Put", key)
	}
}

// keyFromPublicURL extracts the object key from a public delivery URL of the form
// {endpoint}/{bucket}/{key...}. It returns everything after the bucket segment.
func keyFromPublicURL(url, bucket string) string {
	marker := "/" + bucket + "/"
	i := strings.Index(url, marker)
	if i < 0 {
		return ""
	}
	return url[i+len(marker):]
}
