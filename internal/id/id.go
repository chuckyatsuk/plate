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

// VaultKey returns the storage key for an asset's vault original:
// `{account}/{asset-id}` (spec §3.2). This is the per-account prefix that makes
// account isolation structural at the storage layer — never derived from a
// request parameter, always from the caller's account claim.
func VaultKey(account, assetID string) string {
	return account + "/" + assetID
}
