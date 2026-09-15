package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	plate "github.com/chuckyatsuk/plate/internal/plate"
)

// Readiness (Tier 1 monitoring). /readyz used to be a stub that always said
// "ok" — which is exactly how a worker with zero machines went unnoticed for
// days. Now it answers from live checks, each with its own short timeout:
//
//	db       pool ping                              fail → DOWN     (503)
//	storage  HEAD a sentinel key on the bucket      fail → DOWN     (503)
//	worker   age of the newest worker heartbeat     stale → DEGRADED (200)
//	queue    age of the oldest queued job           lag  → DEGRADED (200)
//
// The split is deliberate. DOWN means the API cannot serve the read/write path
// at all, so Fly's check should pull the machine from routing. DEGRADED means
// the API is fine but the background side is not — a dead worker must NEVER
// make the API unroutable (that would turn "video transcodes are late" into
// "no images resolve"). An external monitor alerts on BOTH: HTTP != 200 OR the
// body's status != "ok".
//
// Transitions are logged ONCE (ok→degraded, →down, and back), never per probe,
// so `fly logs` reads as an incident timeline instead of a 15-second drumbeat.

// HealthConfig tunes readiness. Zero values take the defaults below.
type HealthConfig struct {
	// WorkerStaleAfter: a newest heartbeat older than this means the worker is
	// dead or stuck. Default 3× the worker's 30s beat = 90s… rounded up to 2m
	// so a single missed beat during a deploy never pages.
	WorkerStaleAfter time.Duration
	// WorkerProgressWindow: the queue is "stuck" only when it is non-empty AND no
	// job has made progress (been claimed, heartbeated, completed, or failed) within
	// this window. Replaces the old wall-clock lag ceiling, which false-degraded on
	// a healthy worker running one long transcode (the V4 finding: a single 1.3GB
	// detail crossed a 10m oldest-queued ceiling while the worker was fine). A long
	// job keeps progress fresh via its lease heartbeat; a dead/hung worker does not.
	// Default 5m. The oldest-queued age stays in the detail string as INFORMATION.
	WorkerProgressWindow time.Duration
	// CheckTimeout bounds each dependency call so a hung Postgres cannot hang the
	// probe (and the probe's caller). Default 2s.
	CheckTimeout time.Duration
	// Checks is the allowlist of checks to run (db, storage, worker, queue).
	// Empty = all. An operator can narrow it WITHOUT a code deploy if a check
	// misfires (PLATE_READYZ_CHECKS=db,storage).
	Checks []string
	// Version is reported in the Health body (FLY_IMAGE_REF / PLATE_VERSION).
	Version string
}

const (
	defaultWorkerStaleAfter     = 2 * time.Minute
	defaultWorkerProgressWindow = 5 * time.Minute
	defaultCheckTimeout         = 2 * time.Second
	// storageSentinelKey is HEADed to prove the bucket is reachable with valid
	// credentials. It need not exist: a missing object is Exists=false with NO
	// error; a bad endpoint or credential is an error. Outside every account
	// prefix on purpose.
	storageSentinelKey = "healthz/.probe"
)

type health struct {
	cfg  HealthConfig
	log  *slog.Logger
	mu   sync.Mutex
	last plate.HealthStatus // last reported status, for transition logging
}

func newHealth(cfg HealthConfig, log *slog.Logger) *health {
	if log == nil {
		log = slog.Default()
	}
	if cfg.WorkerStaleAfter <= 0 {
		cfg.WorkerStaleAfter = defaultWorkerStaleAfter
	}
	if cfg.WorkerProgressWindow <= 0 {
		cfg.WorkerProgressWindow = defaultWorkerProgressWindow
	}
	if cfg.CheckTimeout <= 0 {
		cfg.CheckTimeout = defaultCheckTimeout
	}
	return &health{cfg: cfg, log: log, last: plate.Ok}
}

func (h *health) enabled(name string) bool {
	if len(h.cfg.Checks) == 0 {
		return true
	}
	for _, c := range h.cfg.Checks {
		if strings.EqualFold(strings.TrimSpace(c), name) {
			return true
		}
	}
	return false
}

func check(ok bool, detail string) *plate.HealthCheck {
	c := &plate.HealthCheck{Ok: ok}
	if detail != "" {
		c.Detail = &detail
	}
	return c
}

// Readiness runs every enabled check and folds them into a Health body plus
// the HTTP status to serve it with.
func (s *Service) Readiness(ctx context.Context) (plate.Health, int) {
	h := s.health
	checks := plate.HealthChecks{}
	down, degraded := false, false

	// db — the API cannot serve without it.
	if h.enabled("db") {
		cctx, cancel := context.WithTimeout(ctx, h.cfg.CheckTimeout)
		err := s.store.Ping(cctx)
		cancel()
		if err != nil {
			checks.Db = check(false, "ping failed: "+errText(err))
			down = true
		} else {
			checks.Db = check(true, "")
		}
	}

	// storage — presign/finalize/original all need it. nil storage = a
	// deliberately read-only deployment (write handlers 501), not a failure.
	if h.enabled("storage") {
		if s.storage == nil {
			checks.Storage = check(true, "not configured (read-only deployment)")
		} else {
			cctx, cancel := context.WithTimeout(ctx, h.cfg.CheckTimeout)
			_, err := s.storage.Head(cctx, storageSentinelKey)
			cancel()
			if err != nil {
				checks.Storage = check(false, "head failed: "+errText(err))
				down = true
			} else {
				checks.Storage = check(true, "")
			}
		}
	}

	// worker — background; its absence degrades, never downs.
	if h.enabled("worker") {
		cctx, cancel := context.WithTimeout(ctx, h.cfg.CheckTimeout)
		wl, err := s.store.WorkerLiveness(cctx)
		cancel()
		switch {
		case err != nil:
			checks.Worker = check(false, "liveness query failed: "+errText(err))
			degraded = true
		case !wl.Seen:
			checks.Worker = check(false, "no worker has ever reported a heartbeat")
			degraded = true
		default:
			age := time.Since(wl.LastSeen).Truncate(time.Second)
			detail := fmt.Sprintf("last heartbeat %s ago", age)
			if wl.LastSweep != nil {
				detail += fmt.Sprintf(", last sweep %s ago", time.Since(*wl.LastSweep).Truncate(time.Second))
			}
			if age > h.cfg.WorkerStaleAfter {
				checks.Worker = check(false, detail+fmt.Sprintf(" (stale > %s)", h.cfg.WorkerStaleAfter))
				degraded = true
			} else {
				checks.Worker = check(true, detail)
			}
		}
	}

	// queue — a live worker that is not draining the queue is still an incident.
	if h.enabled("queue") {
		cctx, cancel := context.WithTimeout(ctx, h.cfg.CheckTimeout)
		ql, err := s.store.QueueLag(cctx)
		cancel()
		switch {
		case err != nil:
			checks.Queue = check(false, "lag query failed: "+errText(err))
			degraded = true
		case ql.Queued == 0:
			checks.Queue = check(true, "empty")
		default:
			// A non-empty queue is an incident only when NOTHING is progressing.
			// The oldest-queued age is information (a long job legitimately lets it
			// climb); the pass/fail signal is whether a worker has advanced ANY job
			// within the progress window. A live worker mid-transcode heartbeats its
			// lease, keeping LastProgress fresh; a dead/hung one lets it go stale.
			age := time.Since(*ql.OldestQueued).Truncate(time.Second)
			detail := fmt.Sprintf("%d queued, oldest %s", ql.Queued, age)
			stuck := ql.LastProgress == nil ||
				time.Since(*ql.LastProgress) > h.cfg.WorkerProgressWindow
			if stuck {
				noProgress := "no job has ever progressed"
				if ql.LastProgress != nil {
					noProgress = fmt.Sprintf("no progress in %s", time.Since(*ql.LastProgress).Truncate(time.Second))
				}
				checks.Queue = check(false, detail+" ("+noProgress+")")
				degraded = true
			} else {
				checks.Queue = check(true, detail)
			}
		}
	}

	status, code := plate.Ok, http.StatusOK
	switch {
	case down:
		status, code = plate.Down, http.StatusServiceUnavailable
	case degraded:
		status = plate.Degraded
	}
	h.logTransition(status, checks)

	body := plate.Health{Status: status, Checks: &checks}
	if h.cfg.Version != "" {
		v := h.cfg.Version
		body.Version = &v
	}
	return body, code
}

// logTransition logs once per status change, naming the failing checks.
func (h *health) logTransition(now plate.HealthStatus, checks plate.HealthChecks) {
	h.mu.Lock()
	prev := h.last
	h.last = now
	h.mu.Unlock()
	if prev == now {
		return
	}
	var failing []string
	for name, c := range map[string]*plate.HealthCheck{"db": checks.Db, "storage": checks.Storage, "worker": checks.Worker, "queue": checks.Queue} {
		if c != nil && !c.Ok {
			d := ""
			if c.Detail != nil {
				d = ": " + *c.Detail
			}
			failing = append(failing, name+d)
		}
	}
	msg := fmt.Sprintf("readiness %s → %s", prev, now)
	if len(failing) > 0 {
		msg += " [" + strings.Join(failing, "; ") + "]"
	}
	if now == plate.Ok {
		h.log.Info(msg)
	} else {
		h.log.Warn(msg)
	}
}

// errText trims an error for a health detail: short, and never account data
// (these errors come from infrastructure, not from account-scoped queries).
func errText(err error) string {
	s := err.Error()
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return s
}

func (s *Service) handleReady(w http.ResponseWriter, r *http.Request) {
	body, code := s.Readiness(r.Context())
	writeJSON(w, code, body)
}
