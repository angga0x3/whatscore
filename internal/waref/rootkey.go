// Package waref holds values that the WhatsApp reference implementation fixes
// for every client. They are shared here so a command (the probe, the server)
// cannot drift from the pinned value, and so re-confirming a finding against
// the live service means editing exactly one file.
package waref

import "encoding/hex"

// RootPubHex is the pinned WhatsApp server certificate root public key recorded
// in docs/protocol/noise.md (PF-009).
//
// It is a public constant, not a credential: the Noise certificate chain
// (msg2.payload) is verified against it, so replacing it with an attacker's
// root would make certificate verification decorative. PF-009 is Confirmed by
// live interop: `cmd/whatscore-probe` completed the handshake against the real
// endpoint, which verifies this chain.
const RootPubHex = "142375574d0a587166aae71ebe516437c4a28b73e3695c6ce1f7f9545da8ee6b"

// RootPublicKey returns a fresh copy of the 32-byte pinned root public key.
//
// The copy matters: callers such as core/engine keep the slice and hand it to
// the handshake, and a shared mutable slice would let any one caller change the
// pinned root for every other session in the process.
func RootPublicKey() []byte {
	out, err := hex.DecodeString(RootPubHex)
	if err != nil || len(out) != 32 {
		// RootPubHex is a compile-time constant; a bad value is a programming
		// error, not a runtime condition.
		panic("waref: pinned root public key is not 32 bytes of hex")
	}
	return out
}
