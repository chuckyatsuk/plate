package service

// The production config is committed in the deploy manifests' [env]; the secrets
// live in Infisical and reach Fly as Fly secrets (docs/SECRETS.md). This file pins
// both halves against the COMMITTED manifests: every config value Plate needs is
// in [env] and passes LoadEnv's own checks, and no secret name is ever assigned
// in any manifest.

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	apiPlateToml    = "../../deploy/fly.api.plate.toml"
	workerPlateToml = "../../deploy/fly.worker.plate.toml"
)

// The config the API reads from [env] (formerly Fly secrets).
var apiEnvConfigNames = []string{
	"IMGPROXY_BASE_URL",
	"IMGPROXY_GRANTED_BASE_URL",
	"PLATE_DOWNLOAD_BASE",
	"PLATE_GRANTED_URL_TTL",
	"PLATE_JWT_REQUIRE_KEY_BINDING", // gitleaks:allow (a config name, not a key; "KEY" trips generic-api-key)
	"R2_DEFAULT_BUCKET",
	"R2_ENDPOINT",
	"R2_PUBLIC_BASE",
	"R2_REGION",
}

// The R2 config the worker reads from [env]; it must equal the API's.
var workerEnvConfigNames = []string{"R2_DEFAULT_BUCKET", "R2_ENDPOINT", "R2_REGION"}

// The secrets: exactly the names in Infisical `plate`/`prod`. None may be
// assigned in a committed manifest.
var plateSecretNames = []string{
	"DATABASE_URL",
	"IMGPROXY_KEY",
	"IMGPROXY_SALT",
	"PLATE_DELIVERY_SIGNING_KEY",
	"R2_ACCESS_KEY_ID",
	"R2_SECRET_ACCESS_KEY",
	"PLATE_JWT_PUBLIC_KEYS",
	"PLATE_JWT_KEY_ACCOUNTS",
}

// envSection returns the body of a manifest's top-level [env] table: from the
// `[env]` header to the next table header (or EOF).
func envSection(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	loc := regexp.MustCompile(`(?m)^\[env\]\s*$`).FindIndex(raw)
	if loc == nil {
		t.Fatalf("%s: no [env] table", path)
	}
	body := raw[loc[1]:]
	if next := regexp.MustCompile(`(?m)^\s*\[`).FindIndex(body); next != nil {
		body = body[:next[0]]
	}
	return body
}

// manifestEnv reads the named keys from a manifest's [env]; each must be present
// and non-empty.
func manifestEnv(t *testing.T, path string, names []string) map[string]string {
	t.Helper()
	body := envSection(t, path)
	out := map[string]string{}
	for _, n := range names {
		v, ok := tomlEnv(t, body, n)
		if !ok {
			t.Errorf("%s: %s missing from [env]", path, n)
			continue
		}
		if v == "" {
			t.Errorf("%s: %s is empty in [env]", path, n)
			continue
		}
		out[n] = v
	}
	return out
}

func TestDeployEnv_ConfigInEnv(t *testing.T) {
	api := manifestEnv(t, apiPlateToml, apiEnvConfigNames)
	worker := manifestEnv(t, workerPlateToml, workerEnvConfigNames)
	if t.Failed() {
		return
	}
	if strings.TrimRight(api["IMGPROXY_BASE_URL"], "/") == strings.TrimRight(api["IMGPROXY_GRANTED_BASE_URL"], "/") {
		t.Errorf("%s: IMGPROXY_GRANTED_BASE_URL must differ from IMGPROXY_BASE_URL (LoadEnv refuses to boot)", apiPlateToml)
	}
	for _, n := range workerEnvConfigNames {
		if worker[n] != api[n] {
			t.Errorf("%s differs: worker %q, api %q (both apps use the same bucket)", n, worker[n], api[n])
		}
	}
}

func TestDeployEnv_NoSecretAssigned(t *testing.T) {
	for _, path := range []string{apiPlateToml, workerPlateToml, publicImgproxyToml, grantedImgproxyToml} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, n := range plateSecretNames {
			if regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(n) + `\s*=`).Match(raw) {
				t.Errorf("%s assigns the secret %s; secrets live in Infisical (docs/SECRETS.md), never in a manifest", path, n)
			}
		}
	}
}

// The API manifest's values must pass the checks LoadEnv and LoadStorage apply at
// boot. The secrets get obvious placeholders (no DB or network is touched); the
// JWT trust list is left empty, so the verifier is deny-all and the
// key-binding guard has nothing to refuse.
func TestDeployEnv_APIValuesPassLoadEnv(t *testing.T) {
	api := manifestEnv(t, apiPlateToml, apiEnvConfigNames)
	if t.Failed() {
		return
	}
	for _, n := range plateSecretNames {
		t.Setenv(n, "")
	}
	t.Setenv("PLATE_JWT_PUBLIC_KEY", "")
	for n, v := range api {
		t.Setenv(n, v)
	}
	t.Setenv("DATABASE_URL", "postgres://placeholder@localhost:5432/plate")
	t.Setenv("R2_ACCESS_KEY_ID", "placeholder")
	t.Setenv("R2_SECRET_ACCESS_KEY", "placeholder")

	// parseDurationOr silently ignores a bad duration, so check it parses.
	ttl, err := time.ParseDuration(api["PLATE_GRANTED_URL_TTL"])
	if err != nil {
		t.Fatalf("PLATE_GRANTED_URL_TTL=%q is not a duration: %v", api["PLATE_GRANTED_URL_TTL"], err)
	}
	if b, err := parseBoolEnv("PLATE_JWT_REQUIRE_KEY_BINDING"); err != nil || !b {
		t.Errorf("PLATE_JWT_REQUIRE_KEY_BINDING must be committed as true; got %v, %v", b, err)
	}

	cfg, err := LoadEnv()
	if err != nil {
		t.Fatalf("LoadEnv refuses the committed API [env]: %v", err)
	}
	if cfg.GrantURLTTL != ttl {
		t.Errorf("GrantURLTTL = %s, want %s", cfg.GrantURLTTL, ttl)
	}
	for _, c := range []struct{ name, got string }{
		{"IMGPROXY_BASE_URL", cfg.URLs.ImageCDNBase},
		{"IMGPROXY_GRANTED_BASE_URL", cfg.URLs.GrantedImageBase},
		{"R2_DEFAULT_BUCKET", cfg.URLs.ImageSourceBucket},
		{"R2_PUBLIC_BASE", cfg.URLs.R2PublicBase},
		{"PLATE_DOWNLOAD_BASE", cfg.URLs.DownloadBase},
	} {
		if c.got != api[c.name] {
			t.Errorf("LoadEnv read %s=%q, manifest has %q", c.name, c.got, api[c.name])
		}
	}

	st, err := LoadStorage(context.Background())
	if err != nil {
		t.Fatalf("LoadStorage refuses the committed API [env]: %v", err)
	}
	if st.Storage == nil {
		t.Fatal("LoadStorage: the write path is not configured")
	}
}
