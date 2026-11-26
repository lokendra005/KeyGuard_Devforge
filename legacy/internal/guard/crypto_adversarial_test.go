package guard

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestMalformedExpandedPrivateKey(t *testing.T) {
	key := testKey(t, "malformed")
	for _, tc := range []struct {
		name string
		at   int
		mask byte
	}{
		{"public_hash", 64, 1},
		{"s1_out_of_range", 128, 0x0f},
		{"s2_out_of_range", 768, 0xf0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := key
			bad.Private = bytes.Clone(key.Private)
			if strings.Contains(tc.name, "out_of_range") {
				bad.Private[tc.at] |= tc.mask
			} else {
				bad.Private[tc.at] ^= tc.mask
			}
			if sig, err := bad.Sign([]byte("message"), ActionContext); err == nil || sig != nil {
				t.Fatal("malformed private key returned a signature")
			}
			path := filepath.Join(t.TempDir(), "key.json")
			if err := WriteJSON(path, bad, false); err != nil {
				t.Fatal(err)
			}
			if _, err := ReadKey(path); err == nil {
				t.Fatal("malformed private key accepted from file")
			}
		})
	}
}

func TestCorruptRoundingComponentDoesNotReleaseInvalidSignature(t *testing.T) {
	k := testKey(t, "rounding")
	// Some changed t0 values still yield valid signatures; output verification is
	// a correctness guard, not a proof of complete expanded-key consistency.
	for _, fill := range []byte{0, 0x55, 0xff} {
		bad := k
		bad.Private = bytes.Clone(k.Private)
		for i := 1536; i < len(bad.Private); i++ {
			bad.Private[i] = fill
		}
		sig, err := bad.Sign([]byte("rounding fault"), ActionContext)
		if err != nil {
			if sig != nil {
				t.Fatal("returned signature on failure")
			}
		} else if !Verify(k.Public, []byte("rounding fault"), sig, ActionContext) {
			t.Fatal("released invalid signature")
		}
	}
}

func TestMLDSAContextAndMessageBoundaries(t *testing.T) {
	k := testKey(t, "boundaries")
	for _, ctx := range []string{"", ActionContext, strings.Repeat("x", 255)} {
		for _, msg := range [][]byte{nil, {0}, {0, 255, 128}, bytes.Repeat([]byte{0xa5}, MaxBody)} {
			sig, err := k.Sign(msg, ctx)
			if err != nil || !Verify(k.Public, msg, sig, ctx) {
				t.Fatalf("context=%d message=%d: %v", len(ctx), len(msg), err)
			}
			if Verify(k.Public, append(bytes.Clone(msg), 0), sig, ctx) {
				t.Fatal("accepted appended NUL")
			}
		}
	}
	ctx := strings.Repeat("x", 256)
	if sig, err := k.Sign(nil, ctx); err == nil || sig != nil {
		t.Fatal("accepted oversized context")
	}
	sig, err := k.Sign(nil, "")
	if err != nil || Verify(k.Public, nil, sig, ctx) {
		t.Fatal("verification accepted oversized context", err)
	}
}

func FuzzMLDSAVerify(f *testing.F) {
	k := testKey(f, "fuzz-verifier")
	msg := []byte("binary\x00message")
	sig, err := k.Sign(msg, ActionContext)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(k.Public, msg, sig, ActionContext)
	f.Add([]byte{}, []byte{}, []byte{}, "")
	f.Fuzz(func(t *testing.T, public, message, signature []byte, context string) {
		if len(public) > 2048 || len(message) > 8192 || len(signature) > 4096 || len(context) > 256 {
			return
		}
		if !Verify(public, message, signature, context) {
			return
		}
		// A verifier accepting a changed message under the same signature breaks binding.
		changed := append(bytes.Clone(message), 0)
		if Verify(public, changed, signature, context) {
			t.Fatal("accepted same signature after message substitution")
		}
	})
}
