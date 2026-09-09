package service

import (
	"context"
	"sync"
	"time"

	"github.com/chuckyatsuk/plate/internal/store"
)

// grantCache is the short-TTL, in-process cache the spec calls for explicitly
// (Q3.B "explicit performance trade"): a 197-tile page is 197 grant checks per
// visitor, so caching the verdict by grant id keeps a granted page affordable.
// The deliberate consequence, decided up front: revocation becomes
// EVENTUALLY-CONSISTENT — effective within one TTL window (seconds), not
// instantly. That trade is the product decision, not an accident, and the TTL is
// short so the window is small.
//
// The cache key is the grant id ALONE. A grant's verdict (live/revoked/expired/
// account + which assets it covers) is a property of the grant, independent of
// which asset in its set is being resolved, so one entry serves every tile of a
// package. Coverage of a specific asset is checked against the cached verdict,
// not re-queried.
//
// It is process-local (each API instance has its own), which is fine: the window
// is per-instance and still bounded by the TTL. Nothing here is a correctness
// boundary — the store query is the source of truth; this only bounds how often
// it runs.
type grantCache struct {
	ttl   time.Duration
	mu    sync.Mutex
	items map[string]grantCacheEntry
}

type grantCacheEntry struct {
	verdict store.GrantVerdict
	expires time.Time
}

func newGrantCache(ttl time.Duration) *grantCache {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &grantCache{ttl: ttl, items: make(map[string]grantCacheEntry)}
}

// resolve returns the grant's verdict, from cache if fresh, otherwise from the
// store (and caches it). The verdict is grant-scoped; the caller checks whether
// it covers the specific asset via store.GrantVerdict.Covers, which is already
// baked into the cached verdict for the (grantID, assetID) pair.
//
// NOTE: because Covers is asset-specific, the cache key includes the asset id —
// otherwise a cached verdict for asset X would wrongly answer coverage for asset
// Y in a different grant. Liveness (revoked/expired/account) is identical across
// assets, so this over-caches slightly but never answers coverage wrong.
func (c *grantCache) resolve(ctx context.Context, st store.Store, grantID, assetID string) (store.GrantVerdict, error) {
	key := grantID + "\x00" + assetID
	now := time.Now()

	c.mu.Lock()
	if e, ok := c.items[key]; ok && now.Before(e.expires) {
		c.mu.Unlock()
		return e.verdict, nil
	}
	c.mu.Unlock()

	v, err := st.ResolveGrantForDelivery(ctx, grantID, assetID)
	if err != nil {
		return store.GrantVerdict{}, err
	}

	c.mu.Lock()
	c.items[key] = grantCacheEntry{verdict: v, expires: now.Add(c.ttl)}
	c.mu.Unlock()
	return v, nil
}
