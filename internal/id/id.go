// Package id generates Plate's service-owned identifiers and storage keys.
//
// Plate owns key generation outright (spec §3.3): the human-readable filename is
// metadata, never identity, and the caller never chooses the key. This removes
// the catalogue coupling in the old upload path (a Mongo dedupe loop) — but more
// importantly it is what makes the per-account key prefix STRUCTURAL: a minted
// key is always `{account}/{asset-id}`, where account is the caller's token
// claim, so one account cannot mint a key into another's bucket path (spec Q4).
package id

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// crockford is Crockford's base32 alphabet — the ULID encoding. No I, L, O, U,
// so ids are unambiguous when read aloud or transcribed.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a fresh ULID string: a 48-bit millisecond timestamp followed by
// 80 bits of randomness, Crockford-base32 encoded to 26 chars. Lexicographically
// sortable by creation time, which is convenient for cursor pagination later.
func New() string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	// 48-bit timestamp, big-endian, in the first 6 bytes.
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	// 80 bits of randomness in the last 10.
	if _, err := rand.Read(b[6:]); err != nil {
		// crypto/rand failing is not a condition a media service can paper over.
		panic(fmt.Sprintf("id: crypto/rand: %v", err))
	}
	return encode(b)
}

// encode renders 16 bytes as 26 Crockford-base32 characters (the ULID layout).
// It treats the 16 bytes as a 128-bit big-endian integer held in two uint64
// halves and pulls 5-bit groups from the least significant end, filling the
// output right-to-left. 26*5 = 130 bits covers the 128-bit value (top two bits 0).
func encode(b [16]byte) string {
	var out [26]byte
	high := binary.BigEndian.Uint64(b[0:8])
	low := binary.BigEndian.Uint64(b[8:16])
	for i := 25; i >= 0; i-- {
		out[i] = crockford[low&0x1f]
		// shift the 128-bit (high:low) value right by 5 bits.
		low = (low >> 5) | (high << 59)
		high >>= 5
	}
	return string(out[:])
}

// The vault/delivery wall is a STORAGE SHAPE, not a per-object ACL (spec §3.1,
// Q5, designer 2026-09-10). Originals live under the `vault/` prefix, renditions
// under `delivery/`. A bucket policy makes ONLY `delivery/*` publicly readable, so
// a vault original is structurally unreachable over the public delivery base — no
// per-object permission to forget, no public URL that could ever name an original.
// imgproxy reads originals via a PRIVATE S3 credential (s3://bucket/vault/...),
// never the public base. These two prefixes are the load-bearing halves of the wall.
const (
	// VaultPrefix is the never-public home of immutable originals.
	VaultPrefix = "vault/"
	// DeliveryPrefix is the publicly-readable home of derived renditions.
	DeliveryPrefix = "delivery/"
)

// VaultKey returns the storage key for an asset's vault original:
// `vault/{account}/{asset-id}` (spec §3.2). The `{account}/` segment is the
// per-account prefix that makes account isolation structural; the `vault/` prefix
// puts every original on the never-public side of the wall. Never derived from a
// request parameter, always from the caller's account claim.
func VaultKey(account, assetID string) string {
	return VaultPrefix + account + "/" + assetID
}

// RenditionKey returns the storage key for a rendition derived from a vault
// original: `delivery/{account}/{asset-id}/{intent}`. It is SHARED by the worker
// (which writes the object here) and the delivery layer (which builds the URL
// pointing here) so the two cannot drift — a rendition marked ready must resolve
// to the exact bytes the worker wrote (the deployed-smoke bug: delivery pointed at
// a different path than the worker wrote). The rendition sits under `delivery/`
// (public side); note it does NOT nest under the vault key — it is a sibling under
// the delivery prefix, sharing only the `{account}/{asset-id}` middle. The intent
// is a string so this package stays free of the generated contract types.
func RenditionKey(vaultKey, intent string) string {
	// vaultKey is `vault/{account}/{asset}`; swap the vault prefix for delivery/
	// and append the intent, so the two sides share the {account}/{asset} identity
	// but live under their own wall-halves. TrimPrefix (not a raw slice) so a key
	// without the vault prefix degrades safely instead of corrupting.
	rel := strings.TrimPrefix(vaultKey, VaultPrefix) // {account}/{asset}
	return DeliveryPrefix + rel + "/" + intent
}
