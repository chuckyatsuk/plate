package service

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/chuckyatsuk/plate/internal/auth"
	plate "github.com/chuckyatsuk/plate/internal/plate"
	"github.com/chuckyatsuk/plate/internal/storage"
	"github.com/chuckyatsuk/plate/internal/store"
)

// stubStore is a handler-level test double for the delivery paths. It embeds the
// Store interface (nil) so any method a test did not expect panics loudly rather
// than answering something plausible. The SQL itself is proven in test/ against
// real Postgres; this only lets the service's routing and URL-shaping be pinned
// without a container.
type stubStore struct {
	store.Store
	assets map[string]plate.Asset        // by account + "/" + id
	grants map[string]store.GrantVerdict // by grant id + "/" + asset id
	purged map[string]bool               // by account + "/" + id
	// accounts is the provisioned set; provisionCalls counts ProvisionAccount.
	accounts       map[string]plate.Account
	provisionCalls int
}

func newStubStore() *stubStore {
	return &stubStore{
		assets:   map[string]plate.Asset{},
		grants:   map[string]store.GrantVerdict{},
		purged:   map[string]bool{},
		accounts: map[string]plate.Account{},
	}
}

func (s *stubStore) put(a plate.Asset) { s.assets[a.Account+"/"+a.Id] = a }

func (s *stubStore) GetAsset(_ context.Context, account, assetID string) (plate.Asset, error) {
	a, ok := s.assets[account+"/"+assetID]
	if !ok {
		return plate.Asset{}, store.ErrNotFound
	}
	return a, nil
}

func (s *stubStore) ResolveGrantForDelivery(_ context.Context, grantID, assetID string) (store.GrantVerdict, error) {
	return s.grants[grantID+"/"+assetID], nil
}

func (s *stubStore) AssetPurged(_ context.Context, account, assetID string) (bool, error) {
	return s.purged[account+"/"+assetID], nil
}

func (s *stubStore) ProvisionAccount(_ context.Context, account string) (plate.Account, bool, error) {
	s.provisionCalls++
	if a, ok := s.accounts[account]; ok {
		return a, false, nil
	}
	a := plate.Account{Id: account, Created: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)}
	s.accounts[account] = a
	return a, true, nil
}

// stubToken mints a legacy (no-kid) token for account with the given scopes.
func stubToken(t *testing.T, priv ed25519.PrivateKey, account string, scopes ...string) string {
	t.Helper()
	tok, err := auth.Sign(priv, auth.Claims{
		Account: account,
		Scope:   scopes,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// stubConfig is the deploy-shaped service config (same imgproxy key/salt/bases
// as the golden) over a stub store and the given verifier.
func stubConfig(st store.Store, verf *auth.Verifier) Config {
	return Config{
		Store:    st,
		Verifier: verf,
		URLs: URLBuilder{
			ImageCDNBase:      "https://plate-img.everysinglefile.com",
			GrantedImageBase:  "https://plate-img-granted.example",
			ImageSourceBucket: "plate",
			R2PublicBase:      "https://r2.example",
			DownloadBase:      "https://plate.example",
		},
		ImgproxyKey:        "6b6579",   // "key"
		ImgproxySalt:       "73616c74", // "salt"
		DeliverySigningKey: "test-delivery-signing-key",
	}
}

func stubService(t *testing.T, st store.Store, verf *auth.Verifier) *Service {
	t.Helper()
	return New(stubConfig(st, verf))
}

// stubStorage presigns every GET (the download edge's success path) and fails
// loudly on anything else.
type stubStorage struct{ storage.Storage }

func (stubStorage) PresignGet(_ context.Context, key string, _ time.Duration) (string, error) {
	return "https://r2.example/presigned/" + key, nil
}

func do(t *testing.T, h http.Handler, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func trimBody(rec *httptest.ResponseRecorder) string { return strings.TrimSpace(rec.Body.String()) }
