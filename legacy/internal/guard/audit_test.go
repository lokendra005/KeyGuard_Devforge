package guard

import (
	"encoding/json"
	"testing"
)

func auditFixture(t *testing.T) (Bundle, KeyFile, map[string]KeyFile) {
	s, g, k := fixture(t)
	audit := testKey(t, "audit")
	raw, _ := json.Marshal(Event{Sequence: 0, Time: 1000, Genesis: &g})
	events := [][]byte{raw}
	for _, name := range []string{"a", "b"} {
		r := signed(t, k["admin"], "resource.create", name, 0, map[string]int{"balance": 10})
		res, e := s.Apply(r, 1000)
		if e != nil {
			t.Fatal(e)
		}
		raw, _ = json.Marshal(Event{Sequence: s.Sequence, Time: 1000, Request: &r, Result: &res})
		events = append(events, raw)
	}
	b, e := SignBundle(events, "test", audit)
	if e != nil {
		t.Fatal(e)
	}
	return b, audit, k
}
func TestAuditReplayTamperAndWitness(t *testing.T) {
	b, audit, _ := auditFixture(t)
	if _, e := VerifyBundle(b, audit.Public, "test", nil); e != nil {
		t.Fatal(e)
	}
	if _, e := VerifyBundle(b, testKey(t, "other").Public, "test", nil); e == nil {
		t.Fatal("untrusted signer")
	}
	if _, e := VerifyBundle(b, audit.Public, "other", nil); e == nil {
		t.Fatal("wrong audience")
	}
	bad := b
	bad.Events = append([][]byte{}, b.Events...)
	bad.Events[1] = []byte(`{}`)
	if _, e := VerifyBundle(bad, audit.Public, "test", nil); e == nil {
		t.Fatal("tamper")
	}
	short, e := SignBundle(b.Events[:2], "test", audit)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyBundle(short, audit.Public, "test", &b.Checkpoint); e == nil {
		t.Fatal("rollback")
	}
	if _, e = VerifyBundle(b, audit.Public, "test", &short.Checkpoint); e != nil {
		t.Fatal(e)
	}
	w := testKey(t, "witness")
	receipt, e := Attest(short, audit.Public, "test", nil, w)
	if e != nil {
		t.Fatal(e)
	}
	receipt, e = Attest(b, audit.Public, "test", &receipt, w)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = Attest(short, audit.Public, "test", &receipt, w); e == nil {
		t.Fatal("witness rollback")
	}
	// Even an audit signer cannot fabricate a transition without a registered action signature.
	forged := append([][]byte{}, b.Events...)
	var event Event
	_ = json.Unmarshal(forged[1], &event)
	event.Request.Envelope.Resource = "fake"
	forged[1], _ = json.Marshal(event)
	fb, _ := SignBundle(forged, "test", audit)
	if _, e = VerifyBundle(fb, audit.Public, "test", nil); e == nil {
		t.Fatal("forged action accepted")
	}
	reordered := append([][]byte{}, b.Events...)
	reordered[1], reordered[2] = reordered[2], reordered[1]
	fb, _ = SignBundle(reordered, "test", audit)
	if _, e = VerifyBundle(fb, audit.Public, "test", nil); e == nil {
		t.Fatal("reorder")
	}
}
func TestMerkleKnownVector(t *testing.T) {
	// RFC6962 leaf H(0x00 || empty) = SHA256 of a single zero byte.
	root, e := Root([][]byte{{}})
	if e != nil {
		t.Fatal(e)
	}
	if root != "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d" {
		t.Fatal(root)
	}
}
