package guard

import (
	"encoding/json"
	"testing"
)

func TestTransferSafetyAndRoles(t *testing.T) {
	initial, _, keys := fixture(t)
	initial.Resources = map[string]Resource{"a": {100, 1}, "b": {25, 1}}
	tests := []struct {
		name, actor string
		version     int64
		body        any
		code        string
	}{
		{"valid", "writer", 1, map[string]any{"to": "b", "amount": 30, "to_version": 1}, ""},
		{"negative", "writer", 1, map[string]any{"to": "b", "amount": -1, "to_version": 1}, "INVALID_TRANSFER"},
		{"zero", "writer", 1, map[string]any{"to": "b", "amount": 0, "to_version": 1}, "INVALID_TRANSFER"},
		{"overdraw", "writer", 1, map[string]any{"to": "b", "amount": 101, "to_version": 1}, "BALANCE_LIMIT"},
		{"source_version", "writer", 2, map[string]any{"to": "b", "amount": 1, "to_version": 1}, "STALE_RESOURCE"},
		{"destination_version", "writer", 1, map[string]any{"to": "b", "amount": 1, "to_version": 2}, "STALE_RESOURCE"},
		{"same_resource", "writer", 1, map[string]any{"to": "a", "amount": 1, "to_version": 1}, "INVALID_TRANSFER"},
		{"auditor", "observer", 1, map[string]any{"to": "b", "amount": 1, "to_version": 1}, "POLICY_DENIED"},
		{"fraction", "writer", 1, map[string]any{"to": "b", "amount": 1.5, "to_version": 1}, "INVALID_BODY"},
		{"unknown_field", "writer", 1, map[string]any{"to": "b", "amount": 1, "to_version": 1, "bypass": true}, "INVALID_BODY"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(initial)
			var s State
			_ = json.Unmarshal(raw, &s)
			r := signed(t, keys[tc.actor], "resource.transfer", "a", tc.version, tc.body)
			_, e := s.Apply(r, 1000)
			if tc.code == "" {
				if e != nil {
					t.Fatal(e)
				}
				if s.Resources["a"].Balance+s.Resources["b"].Balance != 125 {
					t.Fatal("money created")
				}
			} else if ErrorCode(e) != tc.code {
				t.Fatalf("got %v want %s", e, tc.code)
			}
		})
	}
	s := initial
	s.Resources["b"] = Resource{MaxBalance, 1}
	_, e := s.Apply(signed(t, keys["writer"], "resource.transfer", "a", 1, map[string]any{"to": "b", "amount": 1, "to_version": 1}), 1000)
	if ErrorCode(e) != "BALANCE_LIMIT" {
		t.Fatal(e)
	}
}
func TestRecoveryAndPermanentRevocation(t *testing.T) {
	s, _, keys := fixture(t)
	old := keys["writer"]
	if _, e := s.Apply(signed(t, keys["admin"], "subject.quarantine", "writer", 0, struct{}{}), 1000); e != nil {
		t.Fatal(e)
	}
	if e := s.Allowed(Envelope{Subject: "writer", KeyID: old.ID(), Action: "session.create"}); ErrorCode(e) != "REVOKED" {
		t.Fatal(e)
	}
	fresh := testKey(t, "writer")
	en := Enrollment{Subject: "writer", Role: "writer", Public: fresh.Public}
	en.Proof, _ = fresh.Sign(EnrollmentBytes(en), "KIG/enroll/v1")
	body := RecoveryBody{ID: "recover-1", Expires: 1800, Enrollment: en}
	if _, e := s.Apply(signed(t, keys["recovery1"], "recovery.approve", "writer", 0, body), 1000); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Apply(signed(t, keys["recovery1"], "recovery.approve", "writer", 0, body), 1000); ErrorCode(e) != "DUPLICATE_APPROVER" {
		t.Fatal(e)
	}
	if _, e := s.Apply(signed(t, keys["admin"], "recovery.approve", "writer", 0, body), 1000); ErrorCode(e) != "POLICY_DENIED" {
		t.Fatal(e)
	}
	tampered := body
	tampered.Expires++
	if _, e := s.Apply(signed(t, keys["recovery2"], "recovery.approve", "writer", 0, tampered), 1000); ErrorCode(e) != "CONFLICT" {
		t.Fatal(e)
	}
	if _, e := s.Apply(signed(t, keys["recovery2"], "recovery.approve", "writer", 0, body), 1000); e != nil {
		t.Fatal(e)
	}
	if !s.Keys[old.ID()].Revoked || !s.Members["writer"].Active || !s.Recoveries["recover-1"].Complete {
		t.Fatal("recovery state")
	}
	if e := s.Allowed(Envelope{Subject: "writer", KeyID: fresh.ID(), Action: "resource.transfer"}); e != nil {
		t.Fatal(e)
	}
	if e := s.Allowed(Envelope{Subject: "writer", KeyID: old.ID(), Action: "resource.transfer"}); ErrorCode(e) != "REVOKED" {
		t.Fatal(e)
	}
}
func TestEnrollmentProofAndPrivilege(t *testing.T) {
	s, _, keys := fixture(t)
	fresh := testKey(t, "new-user")
	en := Enrollment{Subject: fresh.Subject, Role: "writer", Public: fresh.Public}
	en.Proof, _ = fresh.Sign(EnrollmentBytes(en), "KIG/enroll/v1")
	if _, e := s.Apply(signed(t, keys["writer"], "key.enroll", fresh.Subject, 0, en), 1000); ErrorCode(e) != "POLICY_DENIED" {
		t.Fatal(e)
	}
	bad := en
	bad.Role = "admin"
	if _, e := s.Apply(signed(t, keys["admin"], "key.enroll", fresh.Subject, 0, bad), 1000); ErrorCode(e) != "INVALID_ENROLLMENT" {
		t.Fatal(e)
	}
	if _, e := s.Apply(signed(t, keys["admin"], "key.enroll", fresh.Subject, 0, en), 1000); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Apply(signed(t, keys["admin"], "key.enroll", fresh.Subject, 0, en), 1000); ErrorCode(e) != "CONFLICT" {
		t.Fatal(e)
	}
	if _, e := s.Apply(signed(t, keys["admin"], "key.revoke", keys["recovery1"].ID(), 0, struct{}{}), 1000); ErrorCode(e) != "RECOVERY_PROTECTED" {
		t.Fatal(e)
	}
}

func TestClockRegressionFailsClosed(t *testing.T) {
	s, _, k := fixture(t)
	s.LastTime = 1001
	if _, e := s.Apply(signed(t, k["admin"], "resource.create", "a", 0, map[string]int{"balance": 1}), 1000); ErrorCode(e) != "CLOCK_REGRESSION" {
		t.Fatal(e)
	}
	if len(s.Resources) != 0 {
		t.Fatal("effect during regressed clock")
	}
}
