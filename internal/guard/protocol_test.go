package guard

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func testKey(t testing.TB, s string) KeyFile {
	t.Helper()
	k, e := NewKey(s)
	if e != nil {
		t.Fatal(e)
	}
	return k
}
func fixture(t testing.TB) (State, Genesis, map[string]KeyFile) {
	t.Helper()
	keys := map[string]KeyFile{}
	g := Genesis{Audience: "test"}
	for _, name := range []string{"admin", "recovery1", "recovery2", "writer", "observer"} {
		k := testKey(t, name)
		keys[name] = k
		role := name
		if name == "recovery1" || name == "recovery2" {
			role = "recovery"
		}
		if name == "observer" {
			role = "auditor"
		}
		g.Identities = append(g.Identities, Identity{name, role, k.Public})
	}
	s, e := NewState(g)
	if e != nil {
		t.Fatal(e)
	}
	return s, g, keys
}
func signed(t testing.TB, k KeyFile, action, res string, version int64, body any) Request {
	t.Helper()
	b, e := json.Marshal(body)
	if e != nil {
		t.Fatal(e)
	}
	id, e := RandomID()
	if e != nil {
		t.Fatal(e)
	}
	ch, e := RandomID()
	if e != nil {
		t.Fatal(e)
	}
	r, e := SignRequest(k, Envelope{Audience: "test", Action: action, Resource: res, ResourceVersion: version, Operation: id, Challenge: ch, Expires: 2000}, b, ActionContext)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func TestSignatureAndByteBinding(t *testing.T) {
	k := testKey(t, "alice")
	b := []byte("message")
	sig, e := k.Sign(b, ActionContext)
	if e != nil {
		t.Fatal(e)
	}
	if !Verify(k.Public, b, sig, ActionContext) {
		t.Fatal("valid signature denied")
	}
	for _, tc := range []struct {
		name          string
		pub, msg, sig []byte
		context       string
	}{
		{"body", k.Public, []byte("message!"), sig, ActionContext}, {"context", k.Public, b, sig, ChallengeContext}, {"truncated", k.Public, b, sig[:10], ActionContext}, {"key", testKey(t, "other").Public, b, sig, ActionContext},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if Verify(tc.pub, tc.msg, tc.sig, tc.context) {
				t.Fatal("accepted mutation")
			}
		})
	}
	r := signed(t, k, "resource.create", "a", 0, map[string]int{"balance": 10})
	r.Body = []byte(`{ "balance": 10 }`)
	r.Envelope.BodyHash = Hash(r.Body)
	r.Signature, e = k.Sign(r.Envelope.Bytes(), ActionContext)
	if e != nil {
		t.Fatal(e)
	}
	wire, _ := json.Marshal(r)
	var decoded Request
	if e = StrictJSON(wire, &decoded); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(decoded.Body, r.Body) || decoded.Validate("test", false) != nil {
		t.Fatal("transport changed signed bytes")
	}
}
func TestStrictJSON(t *testing.T) {
	for _, raw := range []string{`{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `{} {}`, `{"a":NaN}`, string([]byte{'"', 0xff, '"'}), `[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[0]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]`} {
		var v any
		if StrictJSON([]byte(raw), &v) == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	var v struct {
		A int `json:"a"`
	}
	if StrictJSON([]byte(`{"a":1,"b":2}`), &v) == nil {
		t.Fatal("unknown field")
	}
	if StrictJSON([]byte(`{"a":1.5}`), &v) == nil {
		t.Fatal("float into integer")
	}
}
func TestCanonicalEncoding(t *testing.T) {
	if got := hex.EncodeToString(fields("ab", "c")); got != "0000000261620000000163" {
		t.Fatal(got)
	}
	if bytes.Equal(fields("ab", "c"), fields("a", "bc")) {
		t.Fatal("ambiguous fields")
	}
	k := testKey(t, "a")
	r := signed(t, k, "resource.create", "a", 0, map[string]int{"balance": 1})
	base := r.Envelope.Bytes()
	mutations := []func(*Envelope){func(e *Envelope) { e.Audience = "other" }, func(e *Envelope) { e.Subject = "b" }, func(e *Envelope) { e.Resource = "b" }, func(e *Envelope) { e.ResourceVersion++ }, func(e *Envelope) { e.Operation = "b" }, func(e *Envelope) { e.Expires++ }, func(e *Envelope) { e.Action = "key.revoke" }, func(e *Envelope) { e.Challenge = Hash([]byte("x")) }}
	for _, change := range mutations {
		e := r.Envelope
		change(&e)
		if bytes.Equal(base, e.Bytes()) || Verify(k.Public, e.Bytes(), r.Signature, ActionContext) {
			t.Fatal("unbound field")
		}
	}
}
func FuzzStrictJSON(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":1,"a":2}`, `[]`, `null`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		var v any
		_ = StrictJSON(b, &v)
	})
}
func BenchmarkMLDSA65(b *testing.B) {
	k := testKey(b, "bench")
	msg := []byte("action binding benchmark")
	sig, e := k.Sign(msg, ActionContext)
	if e != nil {
		b.Fatal(e)
	}
	b.Run("sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, e := k.Sign(msg, ActionContext); e != nil {
				b.Fatal(e)
			}
		}
	})
	b.Run("verify", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if !Verify(k.Public, msg, sig, ActionContext) {
				b.Fatal("verify")
			}
		}
	})
}
