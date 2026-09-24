package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// signer produces short-lived signatures for delivery URLs. Granted-mode
// delivery (spec Q3.B) hands a recipient a URL that is itself a bearer
// capability for a short window: the signature binds the exact object key, the
// intent, the grant it was issued under, and an expiry, so the URL cannot be
// edited to point at another object/intent or replayed past its window. The
// signature travels as `exp` + `sig` query parameters.
//
// This is a minimal HMAC-SHA256 signer over a canonical string. It is
// deliberately NOT the imgproxy URL signer (that has its own key/salt for the
// image CDN); this signs Plate-issued delivery URLs. The `original` escape
// hatch still uses its known-forgeable placeholder until it is migrated onto
// this signer — a separate, test-pinned follow-up — so nothing here changes
// `original`'s shape.
type signer struct {
	key []byte
}

// newSigner returns a signer, or nil if no key is configured. A nil signer
// means granted-mode delivery cannot be served (the handler refuses rather than
// emitting an unsigned, forgeable "granted" URL — fail closed).
func newSigner(key string) *signer {
	if key == "" {
		return nil
	}
	return &signer{key: []byte(key)}
}

// sign appends `exp` and `sig` query parameters to rawURL, binding it to expiry.
// The signed message is the canonical tuple (key path + intent + grant + exp),
// derived from the URL and the caller-supplied fields so a tampered URL fails
// verification. grantID is included so a signature minted for one grant cannot
// be reused to assert access under another.
func (s *signer) sign(rawURL, intent, grantID string, exp time.Time) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		// A malformed base URL is a programming error upstream; return it
		// unsigned so the caller/test fails loudly rather than shipping a URL
		// that looks signed but is not.
		return rawURL
	}
	expUnix := strconv.FormatInt(exp.Unix(), 10)
	mac := s.mac(u.Path, intent, grantID, expUnix)
	q := u.Query()
	q.Set("exp", expUnix)
	q.Set("sig", mac)
	u.RawQuery = q.Encode()
	return u.String()
}

// verify checks a signed URL: the signature matches AND it has not expired.
// Used by the download/delivery edge (and by tests) to prove a URL is a genuine,
// unexpired capability. Returns false for any tamper, missing param, or expiry.
func (s *signer) verify(rawURL, intent, grantID string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	q := u.Query()
	expUnix := q.Get("exp")
	got := q.Get("sig")
	if expUnix == "" || got == "" {
		return false
	}
	exp, err := strconv.ParseInt(expUnix, 10, 64)
	if err != nil || time.Now().After(time.Unix(exp, 0)) {
		return false
	}
	want := s.mac(u.Path, intent, grantID, expUnix)
	return hmac.Equal([]byte(got), []byte(want))
}

// mac computes the raw signature over the canonical message. Fields are joined
// with a NUL that cannot appear in any of them, so distinct field boundaries
// cannot be shifted (e.g. intent "a" + grant "bc" vs "ab" + "c").
func (s *signer) mac(path, intent, grantID, expUnix string) string {
	h := hmac.New(sha256.New, s.key)
	msg := path + "\x00" + intent + "\x00" + grantID + "\x00" + expUnix
	h.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// imgproxySigner produces imgproxy-signed delivery URLs for images (spec §4.1,
// Q3.B). Unlike the download signer above (Plate's own HMAC over a redirect
// URL), this speaks imgproxy's wire format so IMGPROXY itself enforces expiry
// and tamper at the byte edge — Plate never touches image bytes (Q5). The
// signature is HMAC-SHA256 over salt_bytes+path_bytes, URL-safe base64 without
// padding, placed as /{sig}/{path}; for granted URLs, expiry is the
// `exp:{unix}` processing option inside the signed path, which imgproxy 404s
// past. Both key and salt are hex-encoded (IMGPROXY_KEY / IMGPROXY_SALT) and decoded to raw bytes here.
type imgproxySigner struct {
	key  []byte
	salt []byte
}

// newImgproxySigner returns a signer, or nil if either key or salt is missing or
// not valid hex. A nil signer means image URLs cannot be signed; the caller
// falls back to the unsigned public path (fine for public mode, refused for the
// non-public modes — fail closed there, same discipline as the download signer).
func newImgproxySigner(keyHex, saltHex string) *imgproxySigner {
	if keyHex == "" || saltHex == "" {
		return nil
	}
	k, err1 := hex.DecodeString(keyHex)
	s, err2 := hex.DecodeString(saltHex)
	if err1 != nil || err2 != nil || len(k) == 0 || len(s) == 0 {
		return nil
	}
	return &imgproxySigner{key: k, salt: s}
}

// signPath takes the processing path (everything AFTER the signature segment,
// with a leading slash — e.g. "/pr:lightbox/exp:1700000000/plain/acct/asset@jpg")
// and returns the full signed path "/{sig}/pr:lightbox/exp:...". imgproxy verifies
// exactly this.
func (s *imgproxySigner) signPath(path string) string {
	h := hmac.New(sha256.New, s.key)
	h.Write(s.salt)
	h.Write([]byte(path))
	sig := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	return "/" + sig + path
}

// signedImageURL builds a full imgproxy-signed URL for an image intent. base is
// the imgproxy host; preset is the intent name; source is the FULL source URL
// imgproxy fetches (e.g. "s3://bucket/vault/acct/asset"). The signature is the
// leading segment, so imgproxy — which checks ALL URLs once keyed — accepts it.
//
// Two URL shapes, for two DIFFERENTLY-configured imgproxy apps:
//
//   - PUBLIC (exp nil): /{sig}/{preset}/plain/{src}. Served by the presets-only
//     imgproxy (IMGPROXY_ONLY_PRESETS=true, deploy/fly.imgproxy.plate.toml). In
//     that mode imgproxy reads EXACTLY ONE path segment as a ':'-separated preset
//     list and treats everything after it as the source URL, so the bare preset
//     is the whole processing section. This shape is PERSISTED by consumers
//     (Uri's site stores it on media docs) and CDN-cached for a year: it must
//     never change byte-for-byte. Pinned by TestPublicImageURL_Golden.
//
//   - GRANTED (exp set): /{sig}/pr:{preset}/exp:{unix}/plain/{src}. Served by a
//     SEPARATE imgproxy in normal (options) mode, locked to exactly these two
//     options (IMGPROXY_ALLOWED_PROCESSING_OPTIONS=pr,exp,
//     deploy/fly.imgproxy-granted.plate.toml). The presets-only app cannot serve
//     it: there, "exp:{unix}" lands where the source URL must start and imgproxy
//     answers 404 "Invalid URL" — which is why granted images live on their own
//     host. `exp` sits INSIDE the signed path so it cannot be stripped; imgproxy
//     404s the URL past it and caps Cache-Control max-age at the time remaining.
//
// Both shapes are checked against the committed imgproxy configs by
// TestImgproxyURLsValidUnderDeployConfigs.
func (s *imgproxySigner) signedImageURL(base, preset, source string, exp *time.Time) string {
	var path string
	if exp != nil {
		path = fmt.Sprintf("/pr:%s/exp:%d/plain/%s", preset, exp.Unix(), source)
	} else {
		path = fmt.Sprintf("/%s/plain/%s", preset, source)
	}
	return strings.TrimRight(base, "/") + s.signPath(path)
}
