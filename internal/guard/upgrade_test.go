package guard

import (
	"bytes"
	"context"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func migrationClient(t *testing.T, s *Store, protocol int) *Client {
	t.Helper()
	server := httptest.NewServer(Handler(s))
	t.Cleanup(server.Close)
	c, err := NewClient(server.URL, s.Audience, "")
	if err != nil {
		t.Fatal(err)
	}
	c.Protocol = protocol
	return c
}
func upgradeRequest(t *testing.T, s *Store, c *Client, admin KeyFile) (Request, Bundle) {
	t.Helper()
	b, err := s.Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	u, err := PrepareUpgrade(b, s.Audit.Public, s.Audience, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(u)
	r, err := c.Prepare(admin, "protocol.upgrade", "protocol", 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	return r, b
}
func TestSHA384TreeAndSuiteBinding(t *testing.T) {
	if Digest(3, []byte("abc")) != "" {
		t.Fatal("unknown hash suite fell back")
	}
	if Digest(2, []byte("abc")) != "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" {
		t.Fatal("SHA384 known answer")
	}
	root, err := RootForVersion([][]byte{{}}, 2)
	if err != nil || root != "bec021b4f368e3069134e012c2b4307083d3a9bdd206e24e5f0d86e13d6636655933ec2b413465966817a9c208a11717" {
		t.Fatal(root, err)
	}
	var oracle func([][]byte) []byte
	oracle = func(events [][]byte) []byte {
		var data []byte
		if len(events) == 1 {
			data = append([]byte{0}, events[0]...)
		} else {
			n := 1
			for n*2 < len(events) {
				n *= 2
			}
			data = append(append([]byte{1}, oracle(events[:n])...), oracle(events[n:])...)
		}
		h := sha512.Sum384(data)
		return h[:]
	}
	for _, n := range []int{1, 2, 3, 5, 16, 33} {
		events := make([][]byte, n)
		for i := range events {
			events[i] = []byte{byte(i)}
		}
		got, err := RootForVersion(events, 2)
		if err != nil || got != hex.EncodeToString(oracle(events)) {
			t.Fatal("tree split mismatch", n, err)
		}
	}
	if _, err := RootForVersion([][]byte{{}}, 3); err == nil {
		t.Fatal("unknown tree accepted")
	}
	k := testKey(t, "v2")
	e := Envelope{Version: 2, Audience: "test", Action: "resource.create", Resource: "a", Operation: "op", Expires: 2000, Challenge: strings.Repeat("0", 64)}
	r, err := SignRequest(k, e, []byte(`{"balance":1}`), SignatureContext("action", 2))
	if err != nil || r.Validate("test", false) != nil || !r.Verify(k.Public, "action") {
		t.Fatal("valid v2 rejected", err)
	}
	if len(r.Envelope.BodyHash) != 96 || len(r.Digest()) != 96 || len(r.Envelope.Intent()) != 96 || r.Envelope.KeyID != k.ID() {
		t.Fatal("digest suite or stable ID")
	}
	for _, mutate := range []func(*Envelope){
		func(e *Envelope) { e.Version = 1 }, func(e *Envelope) { e.Version = 3 },
		func(e *Envelope) { e.Suite = "ML-DSA-65/SHA-256" }, func(e *Envelope) { e.KeyCommitment = Digest(2, []byte("other")) },
	} {
		bad := r
		mutate(&bad.Envelope)
		if bad.Validate("test", false) == nil && bad.Verify(k.Public, "action") {
			t.Fatal("accepted version/suite/key mutation")
		}
	}
	r.Signature, _ = k.Sign(r.Envelope.Bytes(), ActionContext)
	if r.Verify(k.Public, "action") {
		t.Fatal("v1 context accepted under v2")
	}
}

func TestPostgresV2CutoverPreservesHistoryKeysAndOperations(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	old := migrationClient(t, s, 1)
	next := migrationClient(t, s, 2)
	first, err := old.Act(k["admin"], "resource.create", "a", 0, map[string]int{"balance": 10})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = old.Act(k["admin"], "resource.create", "b", 0, map[string]int{"balance": 0}); err != nil {
		t.Fatal(err)
	}
	fresh := testKey(t, "writer")
	en := Enrollment{Subject: "writer", Role: "writer", Public: fresh.Public}
	en.Proof, _ = fresh.Sign(EnrollmentBytes(en), SignatureContext("enroll", 1))
	recovery := RecoveryBody{ID: "pending-before-cutover", Expires: time.Now().Unix() + 600, Enrollment: en}
	if _, err = old.Act(k["recovery1"], "recovery.approve", "writer", 0, recovery); err != nil {
		t.Fatal(err)
	}
	token, err := old.Session(k["observer"])
	if err != nil {
		t.Fatal(err)
	}
	stale, err := old.Prepare(k["writer"], "resource.transfer", "a", 1, []byte(`{"to":"b","amount":1,"to_version":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r, before := upgradeRequest(t, s, next, k["admin"])
	prior, err := VerifyBundle(before, s.Audit.Public, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	witness := testKey(t, "witness")
	receipt, err := Attest(before, s.Audit.Public, "test", nil, witness)
	if err != nil {
		t.Fatal(err)
	}
	result, err := next.Execute(r)
	if err != nil {
		t.Fatal(err)
	}
	if retry, err := next.Execute(r); err != nil || retry != result {
		t.Fatal("cutover retry", err)
	}
	if _, err = old.Execute(stale); ErrorCode(err) != "PROTOCOL_VERSION" {
		t.Fatal("old pending write", err)
	}
	if _, err = old.Session(k["observer"]); ErrorCode(err) != "PROTOCOL_VERSION" {
		t.Fatal("old issuance", err)
	}
	if _, err = next.State(token); ErrorCode(err) != "UNAUTHORIZED" {
		t.Fatal("old session survived", err)
	}
	after, err := s.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	post, err := VerifyBundle(after, s.Audit.Public, "test", &before.Checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if post.Version() != 2 || after.Checkpoint.Version != 2 || len(after.Checkpoint.Root) != 96 {
		t.Fatal("not v2")
	}
	if !reflect.DeepEqual(before.Events, after.Events[:len(before.Events)]) || !reflect.DeepEqual(prior.Keys, post.Keys) {
		t.Fatal("modified keys or historical bytes")
	}
	for id, m := range prior.Members {
		if post.Members[id].Epoch != m.Epoch+1 {
			t.Fatal("missing cutover epoch")
		}
	}
	for id, op := range prior.Operations {
		if post.Operations[id] != op {
			t.Fatal("lost operation record")
		}
	}
	if len(post.Recoveries) != 0 || len(post.Sessions) != 0 {
		t.Fatal("stale approval or session survived")
	}
	if _, err = VerifyBundle(before, s.Audit.Public, "test", nil); err != nil {
		t.Fatal("old evidence no longer verifiable", err)
	}
	receipt, err = Attest(after, s.Audit.Public, "test", &receipt, witness)
	if err != nil {
		t.Fatal("witness continuity", err)
	}
	if _, err = Attest(before, s.Audit.Public, "test", &receipt, witness); err == nil {
		t.Fatal("witness downgraded")
	}
	// Re-signing a v1 operation under v2 must not create a second effect.
	reused, err := next.PrepareOperation(k["admin"], "resource.create", "duplicate", 0, []byte(`{"balance":10}`), first.Operation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = next.Execute(reused); ErrorCode(err) != "CONFLICT" {
		t.Fatal("cross-version operation reused", err)
	}
	if _, err = next.Act(k["recovery2"], "recovery.approve", "writer", 0, recovery); ErrorCode(err) != "INVALID_ENROLLMENT" {
		t.Fatal("v1 proof admitted by v2", err)
	}
	if _, err = next.Act(k["writer"], "resource.transfer", "a", 1, map[string]any{"to": "b", "amount": 1, "to_version": 1}); err != nil {
		t.Fatal("old key cannot sign v2", err)
	}
	en.Version = 2
	en.Proof, _ = fresh.Sign(EnrollmentBytes(en), SignatureContext("enroll", 2))
	recovery.Enrollment = en
	recovery.ID = "fresh-v2"
	for _, root := range []string{"recovery1", "recovery2"} {
		if _, err = next.Act(k[root], "recovery.approve", "writer", 0, recovery); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = next.Act(fresh, "resource.transfer", "a", 2, map[string]any{"to": "b", "amount": 1, "to_version": 2}); err != nil {
		t.Fatal(err)
	}
	if _, err = next.Session(k["observer"]); err != nil {
		t.Fatal(err)
	}
	anchored := *s
	anchored.MinVersion = 2
	anchored.Anchor = &after.Checkpoint
	if err = anchored.Check(ctx); err != nil {
		t.Fatal("restart/replay after cutover", err)
	}
	// Even the trusted audit signer cannot re-label v2 history as a v1 tree.
	final, err := s.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	final.Checkpoint.Version = 0
	final.Checkpoint.Suite = ""
	final.Checkpoint.Root, _ = Root(final.Events)
	final.Checkpoint.Signature, _ = s.Audit.Sign(final.Checkpoint.Bytes(), CheckpointContext)
	if _, err = VerifyBundle(final, s.Audit.Public, "test", nil); err == nil {
		t.Fatal("audit protocol downgrade accepted")
	}
	// A forged cross-version duplicate event is rejected independently of the server.
	forged := append([][]byte{}, after.Events...)
	forgedState := post
	res, err := forgedState.Apply(reused, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(Event{Sequence: res.Sequence, Time: time.Now().Unix(), Request: &reused, Result: &res})
	forged = append(forged, raw)
	fake, err := SignBundle(forged, "test", s.Audit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = VerifyBundle(fake, s.Audit.Public, "test", nil); err == nil {
		t.Fatal("offline replay accepted v1 operation twice")
	}
}

func TestPostgresUpgradeAttacksAndAtomicRollback(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	old := migrationClient(t, s, 1)
	next := migrationClient(t, s, 2)
	r, before := upgradeRequest(t, s, next, k["admin"])
	var u Upgrade
	if err := json.Unmarshal(r.Body, &u); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Upgrade){
		"version": func(x *Upgrade) { x.Version = 1 }, "suite": func(x *Upgrade) { x.Suite = "SHA-256" },
		"root": func(x *Upgrade) { x.HistoryRoot = strings.Repeat("0", 96) },
		"size": func(x *Upgrade) { x.Previous.Size++ }, "audience": func(x *Upgrade) { x.Previous.Audience = "other" },
		"old_signature": func(x *Upgrade) { x.Previous.Signature = []byte{0} },
		"old_suite":     func(x *Upgrade) { x.Previous.Version = 2; x.Previous.Suite = Suite384 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := u
			change(&bad)
			if _, err := next.Act(k["admin"], "protocol.upgrade", "protocol", 0, bad); err == nil {
				t.Fatal("bad migration accepted")
			}
		})
	}
	if _, err := next.Act(k["writer"], "protocol.upgrade", "protocol", 0, u); ErrorCode(err) != "POLICY_DENIED" {
		t.Fatal("unauthorized upgrade", err)
	}
	if _, err := old.Act(k["admin"], "protocol.upgrade", "protocol", 0, u); ErrorCode(err) != "INVALID_UPGRADE" {
		t.Fatal("v1 signed upgrade", err)
	}
	if _, err := next.Act(k["admin"], "resource.create", "pre-upgrade", 0, map[string]int{"balance": 0}); ErrorCode(err) != "PROTOCOL_VERSION" {
		t.Fatal("implicit upgrade", err)
	}
	conn, err := s.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	// Force the new audit insert to fail after Apply, then retry the exact request.
	if _, err = conn.Exec(ctx, `CREATE FUNCTION reject_cutover() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected insert failure'; END $$; CREATE TRIGGER reject_cutover BEFORE INSERT ON kig_events FOR EACH ROW EXECUTE FUNCTION reject_cutover()`); err != nil {
		t.Fatal(err)
	}
	if _, err = next.Execute(r); err == nil {
		t.Fatal("cutover ignored insert failure")
	}
	var stored []byte
	var schemaVersion int
	if err = conn.QueryRow(ctx, "SELECT state,schema_version FROM kig_authority").Scan(&stored, &schemaVersion); err != nil {
		t.Fatal(err)
	}
	var state State
	if err = json.Unmarshal(stored, &state); err != nil {
		t.Fatal(err)
	}
	if state.Version() != 1 || schemaVersion != 1 || state.Challenges[r.Envelope.Challenge].Intent == "" {
		t.Fatal("partial migration survived rollback")
	}
	if _, err = conn.Exec(ctx, "DROP TRIGGER reject_cutover ON kig_events"); err != nil {
		t.Fatal(err)
	}
	if _, err = old.Act(k["admin"], "resource.create", "raced", 0, map[string]int{"balance": 0}); err != nil {
		t.Fatal(err)
	}
	if _, err = next.Execute(r); ErrorCode(err) != "INVALID_UPGRADE" {
		t.Fatal("stale checkpoint accepted", err)
	}
	fresh, _ := upgradeRequest(t, s, next, k["admin"])
	if _, err = next.Execute(fresh); err != nil {
		t.Fatal(err)
	}
	if _, err = next.Act(k["admin"], "protocol.upgrade", "protocol", 0, u); ErrorCode(err) != "PROTOCOL_VERSION" {
		t.Fatal("second upgrade issued", err)
	}
	// Old executables never set the v2 transaction marker; their state update fails.
	if _, err = conn.Exec(ctx, "UPDATE kig_authority SET state=state WHERE id=1"); err == nil {
		t.Fatal("legacy writer survived cutover")
	}
	if _, err = conn.Exec(ctx, "UPDATE kig_authority SET state=state-'protocol_version',schema_version=1 WHERE id=1"); err == nil {
		t.Fatal("schema downgraded")
	}
	if err = s.Check(ctx); err != nil {
		t.Fatal(err)
	}
	// Simulate restoring an old full backup using owner-only operations. Runtime
	// enforcement must not rely solely on metadata inside that restored database.
	legacy, err := VerifyBundle(before, s.Audit.Public, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(legacy)
	if _, err = conn.Exec(ctx, "ALTER TABLE kig_authority DISABLE TRIGGER kig_protocol_guard; TRUNCATE kig_events"); err != nil {
		t.Fatal(err)
	}
	if _, err = conn.Exec(ctx, "UPDATE kig_authority SET state=$1,schema_version=1", data); err != nil {
		t.Fatal(err)
	}
	for i, raw := range before.Events {
		if _, err = conn.Exec(ctx, "INSERT INTO kig_events(sequence,payload) VALUES($1,$2)", i, raw); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = conn.Exec(ctx, "ALTER TABLE kig_authority ENABLE TRIGGER kig_protocol_guard"); err != nil {
		t.Fatal(err)
	}
	pinned := *s
	pinned.MinVersion = 2
	if err = pinned.Ready(ctx); ErrorCode(err) != "PROTOCOL_VERSION" {
		t.Fatal("v1 backup bypassed external version pin", err)
	}
}

func TestPostgresUpgradeRace(t *testing.T) {
	s, k := dbFixture(t)
	next := migrationClient(t, s, 2)
	u, before := upgradeRequest(t, s, next, k["admin"])
	legacy := prepareDB(t, s, k["admin"], "resource.create", "race", 0, map[string]int{"balance": 1})
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	var a, b error
	go func() { defer wg.Done(); <-start; _, a = s.Execute(context.Background(), u) }()
	go func() { defer wg.Done(); <-start; _, b = s.Execute(context.Background(), legacy) }()
	close(start)
	wg.Wait()
	if !((a == nil && ErrorCode(b) == "PROTOCOL_VERSION") || (b == nil && ErrorCode(a) == "INVALID_UPGRADE")) {
		t.Fatal("non-atomic race outcomes", a, b)
	}
	after, err := s.Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before.Events, after.Events[:len(before.Events)]) {
		t.Fatal("prefix changed")
	}
	if _, err = VerifyBundle(after, s.Audit.Public, "test", nil); err != nil {
		t.Fatal(err)
	}
	if err = s.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresLegacySchemaUpgrade(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	before, err := s.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.connect(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	// Recreate the original deployed schema's version constraint and lack of fence.
	if _, err = c.Exec(ctx, `DROP TRIGGER kig_protocol_guard ON kig_authority;
ALTER TABLE kig_authority DROP CONSTRAINT kig_authority_schema_version_check;
ALTER TABLE kig_authority ADD CONSTRAINT kig_authority_schema_version_check CHECK(schema_version=1)`); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err = s.Migrate(ctx); err != nil {
		t.Fatal("DDL not idempotent", err)
	}
	after, err := s.Export(ctx)
	if err != nil || !reflect.DeepEqual(before.Events, after.Events) {
		t.Fatal("DDL rewrote history", err)
	}
	next := migrationClient(t, s, 2)
	r, _ := upgradeRequest(t, s, next, k["admin"])
	if _, err = next.Execute(r); err != nil {
		t.Fatal(err)
	}
	if err = s.Check(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresFreshV2AndUnknownSuite(t *testing.T) {
	s, k := dbFixtureProtocol(t, 2)
	ctx := context.Background()
	c := migrationClient(t, s, 2)
	if _, err := c.Act(k["admin"], "resource.create", "v2", 0, map[string]int{"balance": 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Check(ctx); err != nil {
		t.Fatal(err)
	}
	old := migrationClient(t, s, 1)
	if _, err := old.Session(k["observer"]); ErrorCode(err) != "PROTOCOL_VERSION" {
		t.Fatal("fresh v2 accepted v1", err)
	}
	r, err := c.Prepare(k["admin"], "resource.create", "altered", 0, []byte(`{"balance":1}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Envelope){func(e *Envelope) { e.Suite = "unknown" }, func(e *Envelope) { e.Version = 3 }, func(e *Envelope) { e.KeyCommitment = Digest(2, []byte("other")) }} {
		bad := r
		change(&bad.Envelope)
		bad.Signature, _ = k["admin"].Sign(bad.Envelope.Bytes(), SignatureContext("action", 2))
		if _, err := c.Execute(bad); err == nil {
			t.Fatal("signed unknown suite/version/key binding accepted")
		}
	}
	b, err := s.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = PrepareUpgrade(b, s.Audit.Public, "test", nil); err == nil {
		t.Fatal("upgraded fresh v2")
	}
	if !bytes.Equal(k["admin"].Public, safePublic(t, b, s.Audit.Public, "admin")) {
		t.Fatal("key changed")
	}
}

func safePublic(t *testing.T, b Bundle, audit []byte, subject string) []byte {
	t.Helper()
	st, err := VerifyBundle(b, audit, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range st.Keys {
		if k.Subject == subject {
			return k.Public
		}
	}
	t.Fatal("missing key")
	return nil
}
