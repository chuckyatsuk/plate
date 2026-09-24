package service

// Every image URL Plate emits must be ACCEPTED by the imgproxy config it is sent
// to. This file pins that against the COMMITTED deploy manifests — the thing the
// earlier signer tests never checked, which is how the 2026-09-24 bug shipped:
// granted image URLs (`/{preset}/exp:{unix}/plain/…`) were well-formed strings
// that the presets-only production imgproxy rejected 404 "Invalid URL".
//
// Docker is not needed: parseImgproxyPath below is a small, faithful model of
// imgproxy v4.0.15's path parser (options/parser/processing_options.go ParsePath,
// parsePathPresets, parsePathOptions, applyURLOptions; url_options.go
// parseURLOptions; url.go DecodeURL/decodePlainURL; apply.go applyExpiresOption,
// applyPresetOption). It models only what Plate emits — presets-only mode, the
// `pr`/`preset` and `exp`/`expires` options, the processing-options allowlist, and
// `plain` sources — and REJECTS anything else, so it can only err toward calling
// a URL invalid, never toward passing a URL imgproxy would refuse. The model is
// itself checked against upstream's own parser test fixtures
// (TestImgproxyModel_MatchesUpstreamFixtures).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chuckyatsuk/plate/internal/mediaspec"
)

const (
	publicImgproxyToml  = "../../deploy/fly.imgproxy.plate.toml"
	grantedImgproxyToml = "../../deploy/fly.imgproxy-granted.plate.toml"
)

// imgproxyConf is the subset of an imgproxy deploy config that decides whether a
// URL path parses.
type imgproxyConf struct {
	onlyPresets    bool
	allowedOptions []string // IMGPROXY_ALLOWED_PROCESSING_OPTIONS; empty = all
	presets        map[string]bool
}

func tomlEnv(t *testing.T, raw []byte, key string) (string, bool) {
	t.Helper()
	re := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(key) + `\s*=\s*"([^"]*)"`)
	m := re.FindSubmatch(raw)
	if m == nil {
		return "", false
	}
	return strings.TrimSpace(string(m[1])), true
}

// loadImgproxyConf reads an imgproxy deploy manifest's [env] the way imgproxy
// reads its environment: IMGPROXY_ONLY_PRESETS (bool, default false),
// IMGPROXY_ALLOWED_PROCESSING_OPTIONS (comma list, default empty = all),
// IMGPROXY_PRESETS (comma-separated name=options; only the names matter here).
func loadImgproxyConf(t *testing.T, path string) imgproxyConf {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	c := imgproxyConf{presets: map[string]bool{}}
	if v, ok := tomlEnv(t, raw, "IMGPROXY_ONLY_PRESETS"); ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			t.Fatalf("%s: IMGPROXY_ONLY_PRESETS=%q is not a bool", path, v)
		}
		c.onlyPresets = b
	}
	if v, ok := tomlEnv(t, raw, "IMGPROXY_ALLOWED_PROCESSING_OPTIONS"); ok && v != "" {
		for _, o := range strings.Split(v, ",") {
			c.allowedOptions = append(c.allowedOptions, strings.TrimSpace(o))
		}
	}
	v, ok := tomlEnv(t, raw, "IMGPROXY_PRESETS")
	if !ok || v == "" {
		t.Fatalf("%s: no IMGPROXY_PRESETS", path)
	}
	for _, def := range strings.Split(v, ",") {
		name, _, found := strings.Cut(def, "=")
		if !found {
			t.Fatalf("%s: malformed preset definition %q", path, def)
		}
		c.presets[strings.TrimSpace(name)] = true
	}
	return c
}

var errImgproxyInvalidURL = errors.New("imgproxy: 404 Invalid URL")

// parseImgproxyPath models imgproxy v4.0.15 ParsePath for the processing path
// (everything AFTER the signature segment). nil = imgproxy would accept it.
func parseImgproxyPath(c imgproxyConf, path string, now time.Time) error {
	if path == "" || path == "/" {
		return fmt.Errorf("%w: empty path", errImgproxyInvalidURL)
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")

	var urlParts []string
	if c.onlyPresets {
		// parsePathPresets: exactly ONE segment is the preset list; the rest is
		// the source URL.
		for _, p := range strings.Split(parts[0], ":") {
			if !c.presets[p] {
				return fmt.Errorf("%w: Unknown preset: %s", errImgproxyInvalidURL, p)
			}
		}
		urlParts = parts[1:]
	} else {
		// parsePathOptions: a bare resize type as the first segment is the
		// deprecated basic format.
		switch parts[0] {
		case "fit", "fill", "fill-down", "force", "auto":
			return fmt.Errorf("%w: deprecated basic URL format", errImgproxyInvalidURL)
		}
		// parseURLOptions: segments are options until the first one with no ':'.
		start := len(parts)
		for i, seg := range parts {
			args := strings.Split(seg, ":")
			if len(args) == 1 {
				start = i
				break
			}
			name := args[0]
			// applyURLOptions: the allowlist is checked against the name AS WRITTEN.
			if len(c.allowedOptions) > 0 && !slices.Contains(c.allowedOptions, name) {
				return fmt.Errorf("%w: Forbidden processing option %s", errImgproxyInvalidURL, name)
			}
			switch name {
			case "preset", "pr":
				for _, p := range args[1:] {
					if !c.presets[p] {
						return fmt.Errorf("%w: Unknown preset: %s", errImgproxyInvalidURL, p)
					}
				}
			case "expires", "exp":
				if len(args[1:]) > 1 {
					return fmt.Errorf("%w: too many expires args", errImgproxyInvalidURL)
				}
				ts, err := strconv.ParseInt(args[1], 10, 64)
				if err != nil {
					return fmt.Errorf("%w: expires %q is not a unix timestamp", errImgproxyInvalidURL, args[1])
				}
				if ts > 0 && ts < now.Unix() {
					return fmt.Errorf("%w: Expired URL", errImgproxyInvalidURL)
				}
			default:
				// Not modelled — Plate never emits it. Reject rather than guess.
				return fmt.Errorf("model: unmodelled processing option %q", name)
			}
		}
		urlParts = parts[start:]
	}

	// DecodeURL / decodePlainURL. Base64 sources are not modelled (Plate emits
	// plain only) and are rejected.
	if len(urlParts) == 0 {
		return fmt.Errorf("%w: Image URL is empty", errImgproxyInvalidURL)
	}
	if urlParts[0] != "plain" || len(urlParts) < 2 {
		return fmt.Errorf("%w: source is not `plain/…` (segment %q read as the source URL)", errImgproxyInvalidURL, urlParts[0])
	}
	enc := strings.Split(strings.Join(urlParts[1:], "/"), "@")
	if enc[0] == "" {
		return fmt.Errorf("%w: Image URL is empty", errImgproxyInvalidURL)
	}
	if len(enc) > 2 {
		return fmt.Errorf("%w: Multiple formats are specified", errImgproxyInvalidURL)
	}
	return nil
}

// splitSignedImageURL strips base and checks the leading /{sig} against key+salt
// exactly as imgproxy does, returning the processing path it would then parse.
func splitSignedImageURL(t *testing.T, fullURL, base string, key, salt []byte) string {
	t.Helper()
	if !strings.HasPrefix(fullURL, base+"/") {
		t.Fatalf("URL %q is not on base %q", fullURL, base)
	}
	rest := strings.TrimPrefix(fullURL, base) // "/{sig}/..."
	sig, path, ok := strings.Cut(strings.TrimPrefix(rest, "/"), "/")
	if !ok {
		t.Fatalf("URL %q has no signature segment", fullURL)
	}
	path = "/" + path
	h := hmac.New(sha256.New, key)
	h.Write(salt)
	h.Write([]byte(path))
	if want := base64.RawURLEncoding.EncodeToString(h.Sum(nil)); sig != want {
		t.Fatalf("signature mismatch for %q", fullURL)
	}
	return path
}

// ── the model is faithful to upstream ─────────────────────────────────────────

func TestImgproxyModel_MatchesUpstreamFixtures(t *testing.T) {
	now := time.Now()
	// Fixtures copied from imgproxy v4.0.15 options/parser/processing_options_test.go.
	presetsOnly := imgproxyConf{onlyPresets: true, presets: map[string]bool{"test1": true, "test2": true}}
	if err := parseImgproxyPath(presetsOnly, "/test1:test2/plain/http://images.dev/lorem/ipsum.jpg@png", now); err != nil {
		t.Errorf("TestParsePathOnlyPresets fixture must parse: %v", err)
	}
	opts := imgproxyConf{presets: map[string]bool{}}
	if err := parseImgproxyPath(opts, "/exp:32503669200/plain/http://images.dev/lorem/ipsum.jpg", now); err != nil {
		t.Errorf("TestParseExpires fixture must parse: %v", err)
	}
	if err := parseImgproxyPath(opts, "/exp:1609448400/plain/http://images.dev/lorem/ipsum.jpg", now); err == nil {
		t.Errorf("TestParseExpiresExpired fixture must be rejected")
	}
	allow := imgproxyConf{allowedOptions: []string{"pr"}, presets: map[string]bool{"test1": true}}
	if err := parseImgproxyPath(allow, "/pr:test1/plain/http://images.dev/lorem/ipsum.jpg", now); err != nil {
		t.Errorf("TestParseAllowedOptions pr fixture must parse: %v", err)
	}
	if err := parseImgproxyPath(allow, "/pr:test1/blur:10/plain/http://images.dev/lorem/ipsum.jpg", now); err == nil ||
		!strings.Contains(err.Error(), "Forbidden processing option blur") {
		t.Errorf("TestParseAllowedOptions blur fixture must be Forbidden; got %v", err)
	}
}

// ── what Plate emits vs what the deploy configs accept ────────────────────────

func newDeployShapeService(pubBase, grantedBase string) *Service {
	return New(Config{
		URLs: URLBuilder{
			ImageCDNBase:      pubBase,
			GrantedImageBase:  grantedBase,
			ImageSourceBucket: "plate",
		},
		ImgproxyKey:  "6b6579",   // "key"
		ImgproxySalt: "73616c74", // "salt"
	})
}

// TestImgproxyURLsValidUnderDeployConfigs is the pin the bug lacked: for EVERY
// preset, the public URL is accepted by the public (presets-only) manifest and
// the granted URL by the granted manifest — using the real Service routing, so a
// URL sent to the wrong host fails here too.
func TestImgproxyURLsValidUnderDeployConfigs(t *testing.T) {
	pubConf := loadImgproxyConf(t, publicImgproxyToml)
	grantedConf := loadImgproxyConf(t, grantedImgproxyToml)
	const pubBase, grantedBase = "https://plate-img.example", "https://plate-img-granted.example"
	svc := newDeployShapeService(pubBase, grantedBase)
	key, salt := []byte("key"), []byte("salt")
	now := time.Now()
	exp := now.Add(GrantedImageMaxTTL)
	vaultKey := "vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F"

	if len(mediaspec.PresetWidths) == 0 {
		t.Fatal("no presets in mediaspec")
	}
	for preset := range mediaspec.PresetWidths {
		pub, ok := svc.signedImageURL(preset, vaultKey, nil)
		if !ok {
			t.Fatalf("%s: public URL not built", preset)
		}
		if err := parseImgproxyPath(pubConf, splitSignedImageURL(t, pub, pubBase, key, salt), now); err != nil {
			t.Errorf("%s: PUBLIC URL rejected by %s: %v\n  %s", preset, publicImgproxyToml, err, pub)
		}

		granted, ok := svc.signedImageURL(preset, vaultKey, &exp)
		if !ok {
			t.Fatalf("%s: granted URL not built", preset)
		}
		gpath := splitSignedImageURL(t, granted, grantedBase, key, salt)
		if err := parseImgproxyPath(grantedConf, gpath, now); err != nil {
			t.Errorf("%s: GRANTED URL rejected by %s: %v\n  %s", preset, grantedImgproxyToml, err, granted)
		}
		// Past its exp the granted URL must be refused (imgproxy enforces it).
		if err := parseImgproxyPath(grantedConf, gpath, exp.Add(time.Second)); err == nil {
			t.Errorf("%s: granted URL must be rejected after exp", preset)
		}
	}
}

// The two shapes are NOT interchangeable — this is why granted images need their
// own host, and the first assertion is exactly the 2026-09-24 production bug.
func TestImgproxyURLs_WrongHostRejected(t *testing.T) {
	pubConf := loadImgproxyConf(t, publicImgproxyToml)
	grantedConf := loadImgproxyConf(t, grantedImgproxyToml)
	now := time.Now()
	s := newImgproxySigner("6b6579", "73616c74")
	src := "s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F"
	exp := now.Add(time.Minute)
	key, salt := []byte("key"), []byte("salt")

	granted := s.signedImageURL("https://h", mediaspec.PresetLightboxMobile, src, &exp)
	if err := parseImgproxyPath(pubConf, splitSignedImageURL(t, granted, "https://h", key, salt), now); err == nil {
		t.Errorf("a granted (exp) URL must be rejected by the presets-only public imgproxy")
	}
	// The OLD granted shape (pre-fix) — rejected by the public config, as observed live.
	old := fmt.Sprintf("/%s/exp:%d/plain/%s", mediaspec.PresetLightboxMobile, exp.Unix(), src)
	if err := parseImgproxyPath(pubConf, old, now); err == nil {
		t.Errorf("the pre-fix granted shape must reproduce the 404 Invalid URL under the public config")
	}

	pub := s.signedImageURL("https://h", mediaspec.PresetLightbox, src, nil)
	if err := parseImgproxyPath(grantedConf, splitSignedImageURL(t, pub, "https://h", key, salt), now); err == nil {
		t.Errorf("a public bare-preset URL must be rejected by the options-mode granted imgproxy")
	}
}

// The granted host's lockdown: presets-only is off there, so the allowlist is
// what keeps "intent, not transformation" structural. Ad-hoc params are refused.
func TestGrantedImgproxy_RefusesAdhocOptions(t *testing.T) {
	c := loadImgproxyConf(t, grantedImgproxyToml)
	if c.onlyPresets {
		t.Fatalf("%s must run in options mode (it must parse exp)", grantedImgproxyToml)
	}
	if !slices.Equal(c.allowedOptions, []string{"pr", "exp"}) {
		t.Fatalf("%s must allow exactly pr,exp; got %v", grantedImgproxyToml, c.allowedOptions)
	}
	now := time.Now()
	exp := now.Add(time.Minute).Unix()
	for _, p := range []string{
		fmt.Sprintf("/pr:lightbox/w:9000/exp:%d/plain/s3://plate/vault/a/b", exp),
		fmt.Sprintf("/pr:lightbox/exp:%d/q:100/plain/s3://plate/vault/a/b", exp),
		fmt.Sprintf("/preset:lightbox/exp:%d/plain/s3://plate/vault/a/b", exp), // long alias not allowlisted
	} {
		if err := parseImgproxyPath(c, p, now); err == nil {
			t.Errorf("granted imgproxy must refuse %q", p)
		}
	}
}

// Uri's site PERSISTS public URLs and they are CDN-cached for a year: the public
// shape must be byte-identical to what shipped before this change. These strings
// were produced by the pre-fix signer (key "key", salt "salt").
func TestPublicImageURL_Golden(t *testing.T) {
	s := newImgproxySigner("6b6579", "73616c74")
	const base = "https://plate-img.everysinglefile.com"
	const src = "s3://plate/vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F"
	golden := map[string]string{
		"thumbnail":         base + "/E6vJTUwEk5pjbK0EXn_n70YhVb1nmPHMG_Q3UDc798c/thumbnail/plain/" + src,
		"grid":              base + "/xWAn8joP_B1PAAIwuo9Wk2FxWtjDyxpz387cvKfeXRs/grid/plain/" + src,
		"lightbox":          base + "/ZOEoHu7Z0DzVm_epX4nYkhwngZJpqOk8NhZNjyRRmuU/lightbox/plain/" + src,
		"lightbox_mobile":   base + "/o-dUbCdwoz49mV7isimHwSqwRAg7KuZ1PT4EdlCzjYc/lightbox_mobile/plain/" + src,
		"zoom_1":            base + "/xd2t8cLm46MUj2Kp_Nv5thQ2dzuTiazMrMSfbLwM2Oc/zoom_1/plain/" + src,
		"zoom_2":            base + "/jwqWchWPlteQSbU235SP4PkWDldz4n8jI5jEF1ZSN24/zoom_2/plain/" + src,
		"zoom_3_nearsquare": base + "/997n7oZvSPQcg-QUK3ovKArWHzK7oRWZKchB6lPzMs8/zoom_3_nearsquare/plain/" + src,
		"zoom_3_standard":   base + "/MmH2piZyZ2kouMAeaGvHODCO94KrnU2Uh8vX23c_wH4/zoom_3_standard/plain/" + src,
		"zoom_3_wide":       base + "/EsczwvwpnfnHpUuU1vw_JqIVcZ8Ct7d1rY5bIAT3tHc/zoom_3_wide/plain/" + src,
	}
	if len(golden) != len(mediaspec.PresetWidths) {
		t.Fatalf("golden covers %d presets, mediaspec has %d", len(golden), len(mediaspec.PresetWidths))
	}
	for preset, want := range golden {
		if got := s.signedImageURL(base, preset, src, nil); got != want {
			t.Errorf("%s: public URL changed — persisted consumer URLs would diverge:\n got %q\nwant %q", preset, got, want)
		}
	}
	// And through the Service: a configured granted host must not move public URLs.
	svc := newDeployShapeService(base, "https://plate-img-granted.example")
	if got, _ := svc.signedImageURL("lightbox", "vault/uriaran/01M2KWA9BQ645WM87MZ4TENG8F", nil); got != golden["lightbox"] {
		t.Errorf("Service public URL changed:\n got %q\nwant %q", got, golden["lightbox"])
	}
}

// No granted host configured ⇒ a granted image refuses (fail closed), rather
// than emitting a URL on the public host that it cannot parse.
func TestGrantedImage_NoGrantedBaseRefuses(t *testing.T) {
	svc := newDeployShapeService("https://plate-img.example", "")
	exp := time.Now().Add(time.Minute)
	if u, ok := svc.signedImageURL("lightbox", "vault/a/b", &exp); ok {
		t.Fatalf("granted image without IMGPROXY_GRANTED_BASE_URL must refuse; got %q", u)
	}
	if _, ok := svc.signedImageURL("lightbox", "vault/a/b", nil); !ok {
		t.Fatalf("public image must still resolve without a granted base")
	}
}
