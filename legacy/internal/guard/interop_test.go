package guard

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSSLInteroperability(t *testing.T) {
	binary, e := exec.LookPath("openssl")
	if e != nil {
		t.Skip("optional independent check needs OpenSSL >=3.5")
	}
	algorithms, e := exec.Command(binary, "list", "-signature-algorithms").CombinedOutput()
	if e != nil || !strings.Contains(string(algorithms), "ML-DSA-65") {
		t.Skip("OpenSSL has no ML-DSA-65 provider")
	}
	k := testKey(t, "interop")
	msg := []byte("KIG FIPS204 interoperability, exact message bytes\x00\xff")
	sig, e := k.Sign(msg, ActionContext)
	if e != nil {
		t.Fatal(e)
	}
	der, e := asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}}, asn1.BitString{Bytes: k.Public, BitLength: len(k.Public) * 8}})
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	for name, b := range map[string][]byte{"public.der": der, "message": msg, "signature": sig} {
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	args := []string{"pkeyutl", "-verify", "-pubin", "-inkey", filepath.Join(dir, "public.der"), "-keyform", "DER", "-rawin", "-in", filepath.Join(dir, "message"), "-sigfile", filepath.Join(dir, "signature"), "-pkeyopt", "context-string:" + ActionContext}
	if b, e := exec.Command(binary, args...).CombinedOutput(); e != nil {
		t.Fatalf("CIRCL signature rejected by OpenSSL: %v %s", e, b)
	}
	args[len(args)-1] = "context-string:" + ChallengeContext
	if _, e = exec.Command(binary, args...).CombinedOutput(); e == nil {
		t.Fatal("OpenSSL accepted wrong context")
	}
	// The other direction uses OpenSSL's generated key and parses only the public SPKI.
	priv := filepath.Join(dir, "openssl-private.pem")
	pub := filepath.Join(dir, "openssl-public.der")
	signed := filepath.Join(dir, "openssl.sig")
	for _, a := range [][]string{{"genpkey", "-algorithm", "ML-DSA-65", "-out", priv}, {"pkey", "-in", priv, "-pubout", "-outform", "DER", "-out", pub}, {"pkeyutl", "-sign", "-inkey", priv, "-rawin", "-in", filepath.Join(dir, "message"), "-out", signed, "-pkeyopt", "context-string:" + ActionContext}} {
		if b, e := exec.Command(binary, a...).CombinedOutput(); e != nil {
			t.Fatalf("OpenSSL: %v %s", e, b)
		}
	}
	public, e := os.ReadFile(pub)
	if e != nil {
		t.Fatal(e)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	rest, e := asn1.Unmarshal(public, &spki)
	if e != nil || len(rest) != 0 {
		t.Fatal("SPKI parse", e)
	}
	signature, e := os.ReadFile(signed)
	if e != nil {
		t.Fatal(e)
	}
	if !Verify(spki.Key.Bytes, msg, signature, ActionContext) {
		t.Fatal("CIRCL rejected OpenSSL signature")
	}
}
