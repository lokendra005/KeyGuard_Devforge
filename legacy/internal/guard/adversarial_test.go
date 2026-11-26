package guard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPendingRecoveryCannotOverrideNewerRecovery(t *testing.T) {
	s, _, keys := fixture(t)
	proposal := func(id string) RecoveryBody {
		k := testKey(t, "writer")
		en := Enrollment{Subject: "writer", Role: "writer", Public: k.Public}
		en.Proof, _ = k.Sign(EnrollmentBytes(en), "KIG/enroll/v1")
		return RecoveryBody{ID: id, Expires: 1800, Enrollment: en}
	}
	stale := proposal("stale")
	fresh := proposal("fresh")
	approve := func(actor string, p RecoveryBody) error {
		_, e := s.Apply(signed(t, keys[actor], "recovery.approve", "writer", 0, p), 1000)
		return e
	}
	if e := approve("recovery1", stale); e != nil {
		t.Fatal(e)
	}
	for _, actor := range []string{"recovery1", "recovery2"} {
		if e := approve(actor, fresh); e != nil {
			t.Fatal(e)
		}
	}
	before, _ := json.Marshal(s)
	if e := approve("recovery2", stale); e == nil {
		t.Fatal("old partial approval replaced the newer recovered key")
	}
	after, _ := json.Marshal(s)
	if string(before) != string(after) {
		t.Fatal("rejected recovery mutated state")
	}
}
func TestStrictJSONRejectsSemanticAliases(t *testing.T) {
	for _, raw := range []string{`{"Balance":10}`, `{"balance":10,"Balance":999}`, `{"balance":null}`} {
		var body struct {
			Balance int64 `json:"balance"`
		}
		if StrictJSON([]byte(raw), &body) == nil {
			t.Errorf("accepted ambiguous integer body: %s", raw)
		}
	}
}

func TestRecoveryFenceAfterAuthorityChanges(t *testing.T) {
	for _, change := range []string{"quarantine", "role-cycle", "key-revoke", "legacy"} {
		t.Run(change, func(t *testing.T) {
			s, _, k := fixture(t)
			newKey := testKey(t, "writer")
			en := Enrollment{Subject: "writer", Role: "writer", Public: newKey.Public}
			en.Proof, _ = newKey.Sign(EnrollmentBytes(en), "KIG/enroll/v1")
			body := RecoveryBody{ID: "pending", Expires: 1800, Enrollment: en}
			if _, e := s.Apply(signed(t, k["recovery1"], "recovery.approve", "writer", 0, body), 1000); e != nil {
				t.Fatal(e)
			}
			apply := func(action, res string, b any) {
				t.Helper()
				if _, e := s.Apply(signed(t, k["admin"], action, res, 0, b), 1000); e != nil {
					t.Fatal(e)
				}
			}
			switch change {
			case "quarantine":
				apply("subject.quarantine", "writer", struct{}{})
			case "role-cycle":
				apply("subject.role", "writer", map[string]string{"role": "auditor"})
				apply("subject.role", "writer", map[string]string{"role": "writer"})
			case "key-revoke":
				apply("key.revoke", k["writer"].ID(), struct{}{})
			case "legacy":
				r := s.Recoveries[body.ID]
				r.Epoch = 0
				s.Recoveries[body.ID] = r
			}
			if _, e := s.Apply(signed(t, k["recovery2"], "recovery.approve", "writer", 0, body), 1000); ErrorCode(e) != "CONFLICT" {
				t.Fatalf("stale proposal accepted: %v", e)
			}
		})
	}
}
func TestPostgresClockRegressionGuardsReadsAndChallenges(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	token, _ := RandomID()
	executeDB(t, s, k["observer"], "session.create", "observer", 0, map[string]string{"token_hash": Hash([]byte(token))})
	req := prepareDB(t, s, k["admin"], "resource.create", "clock-test", 0, map[string]int{"balance": 1})
	conn, e := s.connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(ctx)
	if _, e = conn.Exec(ctx, `UPDATE kig_authority SET state=jsonb_set(state,'{last_time}',to_jsonb($1::bigint)) WHERE id=1`, time.Now().Unix()+3600); e != nil {
		t.Fatal(e)
	}
	for name, call := range map[string]func() error{
		"read": func() error { _, e := s.ReadSession(ctx, token); return e }, "export": func() error { _, e := s.ExportSession(ctx, token); return e }, "readiness": func() error { return s.Ready(ctx) }, "execute": func() error { _, e := s.Execute(ctx, req); return e },
		"issue": func() error {
			env := req.Envelope
			env.Challenge = ""
			r, e := SignRequest(k["admin"], env, req.Body, ChallengeContext)
			if e != nil {
				return e
			}
			_, e = s.Issue(ctx, r)
			return e
		},
	} {
		t.Run(name, func(t *testing.T) {
			if e := call(); ErrorCode(e) != "CLOCK_REGRESSION" {
				t.Fatalf("clock fence missing: %v", e)
			}
		})
	}
}
func TestPostgresCompetingRecoveriesAndLegacyRestart(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	bodies := make([]RecoveryBody, 2)
	requests := make([]Request, 2)
	for i := range bodies {
		key := testKey(t, "writer")
		en := Enrollment{Subject: "writer", Role: "writer", Public: key.Public}
		en.Proof, _ = key.Sign(EnrollmentBytes(en), "KIG/enroll/v1")
		bodies[i] = RecoveryBody{ID: fmt.Sprint("compete-", i), Expires: time.Now().Unix() + 600, Enrollment: en}
		executeDB(t, s, k["recovery1"], "recovery.approve", "writer", 0, bodies[i])
		requests[i] = prepareDB(t, s, k["recovery2"], "recovery.approve", "writer", 0, bodies[i])
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, req := range requests {
		go func(r Request) { <-start; _, e := s.Execute(ctx, r); results <- e }(req)
	}
	close(start)
	successes, conflicts := 0, 0
	for range requests {
		e := <-results
		if e == nil {
			successes++
		} else if ErrorCode(e) == "CONFLICT" {
			conflicts++
		} else {
			t.Fatal(e)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("got %d commits, %d conflicts", successes, conflicts)
	}
	if e := s.Check(ctx); e != nil {
		t.Fatal(e)
	}
	// Pre-hardening persisted recovery metadata had no epoch. It must remain fenced,
	// while valid historical successful actions can still be reconciled at startup.
	c, e := s.connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	if _, e = c.Exec(ctx, `UPDATE kig_authority SET state=jsonb_set(state,'{recoveries}',(SELECT jsonb_object_agg(key,value-'epoch') FROM jsonb_each(state->'recoveries'))) WHERE id=1`); e != nil {
		t.Fatal(e)
	}
	if e = s.Check(ctx); e != nil {
		t.Fatal("legacy history reconciliation failed", e)
	}
}
func TestPostgresStartupRejectsUnauditedSecurityState(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	c, e := s.connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	var original []byte
	if e = c.QueryRow(ctx, "SELECT state FROM kig_authority WHERE id=1").Scan(&original); e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"recovery", "session"} {
		t.Run(kind, func(t *testing.T) {
			var state State
			if e = json.Unmarshal(original, &state); e != nil {
				t.Fatal(e)
			}
			if kind == "recovery" {
				state.Recoveries["not-in-log"] = Recovery{}
			} else {
				state.Sessions[Hash([]byte("forged-token"))] = Session{Subject: "observer", KeyID: k["observer"].ID(), Expires: time.Now().Unix() + 60}
			}
			raw, _ := json.Marshal(state)
			if _, e = c.Exec(ctx, "UPDATE kig_authority SET state=$1 WHERE id=1", raw); e != nil {
				t.Fatal(e)
			}
			if e = s.Check(ctx); e == nil {
				t.Fatal("unaudited state accepted")
			}
		})
	}
	if _, e = c.Exec(ctx, "UPDATE kig_authority SET state=$1 WHERE id=1", original); e != nil {
		t.Fatal(e)
	}
	if e = s.Check(ctx); e != nil {
		t.Fatal(e)
	}
}

func TestEvidenceBudgetAndBoundedFiles(t *testing.T) {
	block := make([]byte, 2*MaxBody)
	events := make([][]byte, int(MaxAuditBytes/int64(len(block)))+1)
	for i := range events {
		events[i] = block
	}
	if _, e := Root(events); e == nil {
		t.Fatal("unverifiable oversized export allowed")
	}
	if _, e := Root([][]byte{make([]byte, 2*MaxBody+1)}); e == nil {
		t.Fatal("oversized event allowed")
	}
	path := filepath.Join(t.TempDir(), "large")
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate((64 << 20) + 1); e != nil {
		t.Fatal(e)
	}
	f.Close()
	var out any
	if ReadJSON(path, &out) == nil {
		t.Fatal("oversized file accepted")
	}
	target := filepath.Join(t.TempDir(), "target")
	if e = WriteFile(target, []byte("original"), false); e != nil {
		t.Fatal(e)
	}
	link := target + "-link"
	if e = os.Symlink(target, link); e != nil {
		t.Fatal(e)
	}
	if WriteFile(link, []byte("replacement"), false) == nil {
		t.Fatal("symlink overwritten")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original" {
		t.Fatal("target altered")
	}
	k := testKey(t, "permissions")
	keypath := target + "-key"
	if e = WriteJSON(keypath, k, false); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(keypath, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadKey(keypath); e == nil {
		t.Fatal("world-readable private key accepted")
	}
}
func TestPostgresAuditByteCapacityRollsBack(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	req := prepareDB(t, s, k["admin"], "resource.create", "capacity", 0, map[string]int{"balance": 1})
	c, e := s.connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	// Storage fault/quota injection exercises the capacity gate without expensive
	// generation of tens of MiB of valid signed fixtures on each reviewer run.
	if _, e = c.Exec(ctx, `INSERT INTO kig_events(sequence,payload) VALUES(99999,convert_to(repeat('x',$1),'UTF8'))`, MaxAuditBytes); e != nil {
		t.Fatal(e)
	}
	var before, after []byte
	if e = c.QueryRow(ctx, "SELECT state FROM kig_authority WHERE id=1").Scan(&before); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Execute(ctx, req); ErrorCode(e) != "CAPACITY" {
		t.Fatal(e)
	}
	if e = c.QueryRow(ctx, "SELECT state FROM kig_authority WHERE id=1").Scan(&after); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("capacity failure consumed a nonce or changed authority")
	}
	if _, e = c.Exec(ctx, "DELETE FROM kig_events WHERE sequence=99999"); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Execute(ctx, req); e != nil {
		t.Fatal("rollback lost retry", e)
	}
	if e = s.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
func FuzzTypedRequest(f *testing.F) {
	for _, seed := range []string{`{}`, `null`, `{"Envelope":{}}`, `{"envelope":{"version":null}}`, `{"body":"AA==","signature":"AA=="}`, `{"envelope":{"version":2,"suite":"ML-DSA-65/SHA-384","key_commitment":"00"},"body":"e30="}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 8192 {
			return
		}
		var r Request
		if StrictJSON(b, &r) != nil {
			return
		}
		canonical, e := json.Marshal(r)
		if e != nil {
			t.Fatal(e)
		}
		var again Request
		if StrictJSON(canonical, &again) != nil || !reflect.DeepEqual(r, again) {
			t.Fatal("typed JSON roundtrip changed meaning")
		}
	})
}

func TestHTTPJSONCharsetAndReady(t *testing.T) {
	s, k := dbFixture(t)
	server := httptest.NewServer(Handler(s))
	defer server.Close()
	client, e := NewClient(server.URL, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	if e = client.Ready(); e != nil {
		t.Fatal(e)
	}
	req := prepareDB(t, s, k["admin"], "resource.create", "charset", 0, map[string]int{"balance": 1})
	raw, _ := json.Marshal(req)
	r, _ := http.NewRequest("POST", server.URL+"/v1/actions", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	resp, e := http.DefaultClient.Do(r)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}
