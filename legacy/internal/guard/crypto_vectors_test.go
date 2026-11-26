package guard

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

//go:embed testdata/crypto-vectors.json.gz
var cryptoVectors []byte

func TestIndependentMLDSAVectors(t *testing.T) {
	var corpus struct {
		Keygen, Siggen, Verify []struct {
			ID, Seed, PK, SK, Msg, Ctx, Sig string
			Deterministic, Valid            bool
		}
	}
	z, err := gzip.NewReader(bytes.NewReader(cryptoVectors))
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if err := json.NewDecoder(z).Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus.Keygen) != 25 || len(corpus.Siggen) != 30 || len(corpus.Verify) != 225 {
		t.Fatal("incomplete pinned corpus")
	}
	decode := func(s string) []byte {
		t.Helper()
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, tc := range corpus.Keygen {
		t.Run(tc.ID, func(t *testing.T) {
			seed := decode(tc.Seed)
			if len(seed) != mldsa65.SeedSize {
				t.Fatal("invalid seed fixture")
			}
			pk, sk := mldsa65.NewKeyFromSeed((*[mldsa65.SeedSize]byte)(seed))
			if !bytes.Equal(pk.Bytes(), decode(tc.PK)) || !bytes.Equal(sk.Bytes(), decode(tc.SK)) {
				t.Fatal("NIST key generation known-answer mismatch")
			}
		})
	}
	for _, tc := range corpus.Siggen {
		t.Run(tc.ID, func(t *testing.T) {
			var sk mldsa65.PrivateKey
			if err := sk.UnmarshalBinary(decode(tc.SK)); err != nil {
				t.Fatal(err)
			}
			msg, ctx, expected := decode(tc.Msg), decode(tc.Ctx), decode(tc.Sig)
			pub := sk.Public().(*mldsa65.PublicKey).Bytes()
			if !Verify(pub, msg, expected, string(ctx)) {
				t.Fatal("NIST signature rejected by application verifier")
			}
			if tc.Deterministic {
				sig := make([]byte, mldsa65.SignatureSize)
				if err := mldsa65.SignTo(&sk, msg, ctx, false, sig); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(sig, expected) {
					t.Fatal("NIST deterministic signing known-answer mismatch")
				}
			}
			// Production signing remains randomized; never replace global crypto/rand.
			k := KeyFile{Subject: "public-test-vector", Public: pub, Private: decode(tc.SK)}
			if sig, err := k.Sign(msg, string(ctx)); err != nil || !Verify(pub, msg, sig, string(ctx)) {
				t.Fatal("application signing failed on NIST key", err)
			}
		})
	}
	valid, invalid, wycheproof := 0, 0, 0
	for _, tc := range corpus.Verify {
		if tc.Valid {
			valid++
		} else {
			invalid++
		}
		if strings.HasPrefix(tc.ID, "Wycheproof/") {
			wycheproof++
		}
		t.Run(tc.ID, func(t *testing.T) {
			if got := Verify(decode(tc.PK), decode(tc.Msg), decode(tc.Sig), string(decode(tc.Ctx))); got != tc.Valid {
				t.Fatalf("verification got %v, independent expectation %v", got, tc.Valid)
			}
		})
	}
	if wycheproof != 210 || invalid == 0 || valid == 0 {
		t.Fatal("missing positive or adversarial verification vectors")
	}
	t.Logf("25 NIST keygen, 15 deterministic signing KATs, 30 NIST signature checks; 225 verification cases (%d valid, %d invalid; 210 Wycheproof)", valid, invalid)
}
