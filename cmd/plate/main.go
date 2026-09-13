// Command plate is Plate's single binary with two commands (spec Q4): `plate
// serve` (the API) and `plate work` (the worker). Splitting them from day one —
// same binary, different command — is what keeps the API's HA profile and the
// worker's fat, retryable, CPU-bound profile from contaminating each other.
//
// Phase 1 (spec §8) is the read path only: `serve` runs; `work` is a stub that
// refuses, so the shape exists but no worker is claimed to work yet.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/chuckyatsuk/plate/internal/auth"
	"github.com/chuckyatsuk/plate/internal/mediaspec"
	"github.com/chuckyatsuk/plate/internal/service"
	"github.com/chuckyatsuk/plate/internal/store"
	"github.com/chuckyatsuk/plate/internal/worker"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: plate <serve|work|accounts|token|keypair|imgproxy-presets>")
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)) // structured logs to stdout (twelve-factor)

	switch os.Args[1] {
	case "serve":
		if err := serve(log); err != nil {
			log.Error("serve failed", "err", err)
			os.Exit(1)
		}
	case "work":
		if err := work(log); err != nil {
			log.Error("work failed", "err", err)
			os.Exit(1)
		}
	case "imgproxy-presets":
		// Print the IMGPROXY_PRESETS value from mediaspec — the SINGLE source of
		// truth the tests verify against (spec C1). The imgproxy deploy sources its
		// presets from this, so the presets production serves cannot drift from the
		// ones the image-clamp tests prove. Not a running mode; a config emitter.
		fmt.Println(mediaspec.PresetDefs())
	case "accounts":
		if err := accounts(log); err != nil {
			log.Error("accounts failed", "err", err)
			os.Exit(1)
		}
	case "token":
		if err := mintToken(); err != nil {
			log.Error("token failed", "err", err)
			os.Exit(1)
		}
	case "keypair":
		if err := genKeypair(); err != nil {
			log.Error("keypair failed", "err", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "plate: unknown command %q (want serve|work|accounts|token|keypair|imgproxy-presets)\n", os.Args[1])
		os.Exit(2)
	}
}

// accounts is the control-plane subcommand for account lifecycle. Today it does
// one thing — `plate accounts create <id> [--bucket B] [--prefix P]` — the
// out-of-band provisioning step an account needs before its first upload (there
// is deliberately no POST /v1/accounts yet; account lifecycle is an operator
// action, not a data-plane verb — spec Q2). Reuses the same DATABASE_URL the
// server does.
func accounts(log *slog.Logger) error {
	fs := flag.NewFlagSet("accounts", flag.ExitOnError)
	bucket := fs.String("bucket", "", "per-account storage bucket (optional; defaults to the deployment bucket)")
	prefix := fs.String("prefix", "", "per-account storage prefix (optional)")
	// os.Args: plate accounts create <id> [flags]
	if len(os.Args) < 4 || os.Args[2] != "create" {
		return fmt.Errorf("usage: plate accounts create <account-id> [--bucket B] [--prefix P]")
	}
	accountID := os.Args[3]
	if err := fs.Parse(os.Args[4:]); err != nil {
		return err
	}
	if accountID == "" {
		return fmt.Errorf("account id is required: plate accounts create <account-id>")
	}

	ctx := context.Background()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	st, err := store.Open(ctx, dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.CreateAccount(ctx, accountID, *bucket, *prefix); err != nil {
		return err
	}
	log.Info("account provisioned", "id", accountID, "bucket", *bucket, "prefix", *prefix)
	return nil
}

// knownScopes is the closed set of scopes the token model understands (spec Q3,
// mirrored in internal/auth). Minting a token with a scope outside this set would
// silently produce a credential that grants nothing — a typo that looks configured
// but isn't — so `plate token` rejects unknown scopes up front.
var knownScopes = map[string]bool{
	"assets:read":         true,
	"assets:write":        true,
	"renditions:generate": true,
	"grants:manage":       true,
	"assets:export":       true,
}

// mintToken is the operator subcommand that issues a scoped service token:
//
//	plate token <account> --scopes assets:read,assets:write [--ttl 90d] [--sub label]
//
// It is deliberately an OPERATOR action, run out-of-band, NOT a data-plane verb —
// the same posture as `plate accounts create`. Issuance is separable from
// validation (spec Q3): the deployed SERVICE holds only the public key and never
// mints; this command signs with the PRIVATE key, which the operator supplies via
// PLATE_JWT_PRIVATE_B64 (base64 of the Ed25519 private key, as in ~/Dev/plate/.env).
// It never touches the database and never runs on the server.
//
// The token is a bounded credential: it always carries an expiry (--ttl), so a
// leak has a horizon and the credential is rotatable. Plate has no revocation
// list — killing a token before its ttl means rotating the signing key, which
// invalidates every token — so keep the ttl to the shortest that is operationally
// tolerable. This replaces the ad-hoc 2h mint in .scratch/smoketool for anything
// beyond a throwaway smoke.
func mintToken() error {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	scopesCSV := fs.String("scopes", "", "comma-separated scopes (assets:read,assets:write,renditions:generate,grants:manage,assets:export)")
	ttlStr := fs.String("ttl", "720h", "token lifetime, e.g. 90d, 720h, 30m (bounded; the token always expires)")
	sub := fs.String("sub", "operator", "the token's subject claim (a label for who/what it is for)")
	kid := fs.String("kid", "", "key id: names the signing key in the token's kid header, so the server verifies it against PLATE_JWT_PUBLIC_KEYS[kid] — retiring that kid revokes the token. Empty mints a legacy no-kid token (verified by PLATE_JWT_PUBLIC_KEY).")
	// os.Args: plate token <account> [flags]
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: plate token <account> --scopes s1,s2 [--ttl 90d] [--sub label] [--kid name]")
	}
	account := os.Args[2]
	if account == "" || strings.HasPrefix(account, "-") {
		return fmt.Errorf("account id is required: plate token <account> --scopes ...")
	}
	if err := fs.Parse(os.Args[3:]); err != nil {
		return err
	}

	// Scopes: required, and every one must be known.
	scopes := splitCSV(*scopesCSV)
	if len(scopes) == 0 {
		return fmt.Errorf("--scopes is required (e.g. --scopes assets:read,assets:write)")
	}
	for _, s := range scopes {
		if !knownScopes[s] {
			return fmt.Errorf("unknown scope %q (known: assets:read, assets:write, renditions:generate, grants:manage, assets:export)", s)
		}
	}

	ttl, err := parseTTL(*ttlStr)
	if err != nil {
		return err
	}
	if ttl <= 0 {
		return fmt.Errorf("--ttl must be positive")
	}

	privB64 := os.Getenv("PLATE_JWT_PRIVATE_B64")
	if privB64 == "" {
		return fmt.Errorf("PLATE_JWT_PRIVATE_B64 is required (base64 of the Ed25519 private key; operator-held, e.g. ~/Dev/plate/.env)")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(privB64))
	if err != nil {
		return fmt.Errorf("PLATE_JWT_PRIVATE_B64 is not valid base64: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return fmt.Errorf("PLATE_JWT_PRIVATE_B64 decodes to %d bytes, want %d (an Ed25519 private key)", len(raw), ed25519.PrivateKeySize)
	}
	priv := ed25519.PrivateKey(raw)

	now := time.Now()
	claims := auth.Claims{
		Account: account,
		Scope:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   *sub,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	var tok string
	if *kid != "" {
		// A kid names the key — mint-side validation mirrors the server's boot
		// check (PLATE_JWT_PUBLIC_KEYS parsing), so we cannot mint a token whose
		// kid the server could never have configured.
		if !validKidArg(*kid) {
			return fmt.Errorf("--kid %q must be [A-Za-z0-9_-]{1,64}", *kid)
		}
		tok, err = auth.SignWithKid(priv, *kid, claims)
	} else {
		tok, err = auth.Sign(priv, claims)
	}
	if err != nil {
		return err
	}

	// The token itself is the ONLY thing on STDOUT, so `plate token ... > file`
	// captures a clean credential with no log lines mixed in. The process logger
	// writes JSON to stdout (main()), which would pollute that pipe — so the
	// human-readable summary goes explicitly to STDERR instead. No secret in the
	// summary — just its shape.
	fmt.Println(tok)
	kidNote := *kid
	if kidNote == "" {
		kidNote = "(none — legacy key)"
	}
	fmt.Fprintf(os.Stderr, "token minted: account=%s scopes=%s sub=%s kid=%s expires=%s (ttl %s)\n",
		account, strings.Join(scopes, ","), *sub, kidNote,
		now.Add(ttl).UTC().Format(time.RFC3339), ttl.String())
	return nil
}

// validKidArg mirrors the server's kid rule (internal/service parseKeyset):
// plain [A-Za-z0-9_-]{1,64} names only, so a minted kid is always one the
// server's PLATE_JWT_PUBLIC_KEYS parser would accept.
func validKidArg(kid string) bool {
	if len(kid) == 0 || len(kid) > 64 {
		return false
	}
	for _, r := range kid {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// genKeypair generates a fresh Ed25519 keypair for the credential model: the
// PUBLIC half goes into the server's trusted set (PLATE_JWT_PUBLIC_KEYS as
// `<kid>=<public>`, or legacy PLATE_JWT_PUBLIC_KEY), the PRIVATE half is the
// consumer/operator-held signing key (PLATE_JWT_PRIVATE_B64 for `plate token`).
// Promoted from the .scratch smoketool so key generation is a first-class,
// documented operator step instead of a scratch script.
//
// Output shape follows `plate token`: machine-readable halves on STDOUT (two
// labeled lines, stable format), guidance on STDERR. The private half is a
// SECRET — capture it straight into a secret store or env file, never a repo.
func genKeypair() error {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	fmt.Printf("public=%s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("private=%s\n", base64.StdEncoding.EncodeToString(priv))
	fmt.Fprintln(os.Stderr, "keypair generated. public → the server's trusted set (PLATE_JWT_PUBLIC_KEYS entry `<kid>=<public>`, or PLATE_JWT_PUBLIC_KEY); private → the issuer's PLATE_JWT_PRIVATE_B64. The private half is a SECRET — store it in a secret manager or a gitignored env file, never a repo.")
	return nil
}

// splitCSV splits a comma list, trimming spaces and dropping empties.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseTTL extends time.ParseDuration with a `d` (days) suffix — operators think
// in days for a credential lifetime, and Go's parser stops at hours. `90d` →
// 90*24h; everything else defers to time.ParseDuration (h/m/s).
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		var days float64
		if _, err := fmt.Sscanf(strings.TrimSuffix(s, "d"), "%g", &days); err != nil {
			return 0, fmt.Errorf("invalid --ttl %q: %w", s, err)
		}
		return time.Duration(days * 24 * float64(time.Hour)), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid --ttl %q (use e.g. 90d, 720h, 30m): %w", s, err)
	}
	return d, nil
}

func serve(log *slog.Logger) error {
	ctx := context.Background()

	cfg, err := service.LoadEnv()
	if err != nil {
		return err
	}

	// Run migrations at boot — the SAME migrations the test container runs, so
	// there is one schema and no drift (spec §6).
	if err := store.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	// Write-path deps (storage + prober) are opt-in by config: absent R2 config
	// means a read-path-only deployment (write endpoints answer 503). A PARTIAL R2
	// config fails fast here rather than accepting traffic and erroring per request
	// (review ruling 7).
	sc, err := service.LoadStorage(ctx)
	if err != nil {
		return err
	}
	if sc.Storage != nil {
		log.Info("write path enabled (storage configured)")
	} else {
		log.Info("read-path-only (no storage configured; write endpoints return 503)")
	}

	// Loud-at-boot for the looks-configured-but-isn't traps (the empty Fly
	// secret, 2026-09-13): these states are LEGAL (the quickstart .env.example
	// ships them empty) but must never be silent — the failure otherwise
	// surfaces as a bare 503/401 at first use, far from its cause.
	if !cfg.Verifier.Configured() {
		log.Warn("no token validation key configured (PLATE_JWT_PUBLIC_KEY / PLATE_JWT_PUBLIC_KEYS empty) — every authenticated request will 401")
	}
	if cfg.DeliverySigningKey == "" {
		log.Warn("PLATE_DELIVERY_SIGNING_KEY is empty — granted A/V, owner-original downloads, and exports will refuse (503); check the deployed secret is not present-but-empty")
	}

	svc := service.New(service.Config{
		Store:              st,
		Verifier:           cfg.Verifier,
		URLs:               cfg.URLs,
		Storage:            sc.Storage,
		Prober:             sc.Prober,
		UploadTTL:          sc.UploadTTL,
		UploadMaxBytes:     sc.UploadMaxBytes,
		DeliverySigningKey: cfg.DeliverySigningKey,
		ImgproxyKey:        cfg.ImgproxyKey,
		ImgproxySalt:       cfg.ImgproxySalt,
		GrantURLTTL:        cfg.GrantURLTTL,
		GrantCacheTTL:      cfg.GrantCacheTTL,
	})

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           svc.Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful SIGTERM shutdown (K8s-ready, spec Q4).
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Info("plate serve", "addr", cfg.HTTPAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// work runs the transcode worker (spec §5.2, Q4). Unlike serve, storage is
// REQUIRED — the worker's whole job is pulling originals and writing renditions.
func work(log *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := service.LoadEnv()
	if err != nil {
		return err
	}
	sc, err := service.LoadStorage(ctx)
	if err != nil {
		return err
	}
	if sc.Storage == nil {
		return fmt.Errorf("plate work: storage is required (set R2_ENDPOINT / R2_DEFAULT_BUCKET)")
	}

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	w := worker.New(worker.Config{
		Store:              st,
		Storage:            sc.Storage,
		Transcoder:         worker.NewFFmpegTranscoder(os.Getenv("PLATE_FFMPEG_PATH"), "", 0),
		Prober:             sc.Prober,
		Log:                log,
		ScratchDir:         os.Getenv("PLATE_WORKER_SCRATCH_DIR"),
		DetailMaxDurationS: service.DetailMaxDurationSeconds(), // PLATE_DETAIL_MAX_DURATION, default 720
	})

	// The reconciliation sweeps (orphaned uploads + two-step deleted-asset purge,
	// spec §5.1/§Q2) run on a ticker inside the worker — the scheduler they were
	// built for but never had. Kept in-process (not a separate Fly cron machine):
	// the worker already holds the store + storage, and the sweeps are periodic
	// housekeeping. Interval + grace are env-tunable; defaults are safe.
	reconciler := worker.NewReconciler(st, sc.Storage, log,
		parseDurationEnv("PLATE_SWEEP_GRACE", 0), // 0 → 6h default
		0,                                        // batch size default (100)
	)
	go reconciler.SweepLoop(ctx, parseDurationEnv("PLATE_SWEEP_EVERY", 15*time.Minute))

	// Graceful SIGTERM: cancel the loop's context so an in-flight job finishes or
	// releases its lease, then exit (K8s-ready, spec Q4). This also stops SweepLoop.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		log.Info("worker: signal received, stopping")
		cancel()
	}()

	log.Info("plate work")
	if err := w.Run(ctx); err != nil && err != context.Canceled {
		return err
	}
	return nil
}

// parseDurationEnv reads a Go duration from an env var, falling back to def on
// absent/invalid. Small local helper so the worker's tunables read from one place.
func parseDurationEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
