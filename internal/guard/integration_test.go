package guard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func dbFixture(t testing.TB) (*Store, map[string]KeyFile) {
	return dbFixtureProtocol(t, 1)
}
func dbFixtureProtocol(t testing.TB, version int) (*Store, map[string]KeyFile) {
	t.Helper()
	dsn := os.Getenv("KIG_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set KIG_TEST_DATABASE_URL or run make test for real PostgreSQL integration")
	}
	ctx := context.Background()
	conn, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	id, e := RandomID()
	if e != nil {
		t.Fatal(e)
	}
	name := "kig_test_" + id[:16]
	if _, e = conn.Exec(ctx, "CREATE SCHEMA "+name); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() {
		_, e := conn.Exec(ctx, "DROP SCHEMA "+name+" CASCADE")
		if e != nil {
			t.Error(e)
		}
		conn.Close(ctx)
	})
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	q := u.Query()
	q.Set("search_path", name)
	u.RawQuery = q.Encode()
	_, g, keys := fixture(t)
	if version == 2 {
		g.Version = 2
		g.Suite = Suite384
	}
	store := &Store{DSN: u.String(), Audience: "test", Audit: testKey(t, "audit")}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = store.Migrate(ctx); e != nil {
		t.Fatal(e)
	}
	if e = store.Init(ctx, g); e != nil {
		t.Fatal(e)
	}
	if e = store.Check(ctx); e != nil {
		t.Fatal(e)
	}
	return store, keys
}
func prepareDB(t testing.TB, s *Store, k KeyFile, action, res string, version int64, body any) Request {
	t.Helper()
	raw, _ := json.Marshal(body)
	op, _ := RandomID()
	env := Envelope{Audience: s.Audience, Action: action, Resource: res, ResourceVersion: version, Operation: op, Expires: time.Now().Unix() + 60}
	r, e := SignRequest(k, env, raw, ChallengeContext)
	if e != nil {
		t.Fatal(e)
	}
	reply, e := s.Issue(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	env.Challenge = reply.Challenge
	r, e = SignRequest(k, env, raw, ActionContext)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func executeDB(t testing.TB, s *Store, k KeyFile, action, res string, version int64, body any) Result {
	t.Helper()
	r := prepareDB(t, s, k, action, res, version, body)
	v, e := s.Execute(context.Background(), r)
	if e != nil {
		t.Fatal(e)
	}
	return v
}
func seedResources(t testing.TB, s *Store, keys map[string]KeyFile) {
	t.Helper()
	for _, id := range []string{"a", "b"} {
		executeDB(t, s, keys["admin"], "resource.create", id, 0, map[string]int{"balance": 100})
	}
}
func TestPostgresConcurrencyReplayAndRestart(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	seedResources(t, s, k)
	req := prepareDB(t, s, k["writer"], "resource.transfer", "a", 1, map[string]any{"to": "b", "amount": 20, "to_version": 1})
	const n = 12
	results := make(chan Result, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); copyStore := *s; r, e := copyStore.Execute(ctx, req); results <- r; errs <- e }()
	}
	wg.Wait()
	close(results)
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var seq int64
	for r := range results {
		if seq == 0 {
			seq = r.Sequence
		}
		if r.Sequence != seq {
			t.Fatal("duplicate effect")
		}
	}
	b, e := s.Export(ctx)
	if e != nil {
		t.Fatal(e)
	}
	st, e := VerifyBundle(b, s.Audit.Public, "test", nil)
	if e != nil {
		t.Fatal(e)
	}
	if st.Resources["a"].Balance != 80 || st.Resources["b"].Balance != 120 {
		t.Fatal(st.Resources)
	}
	restarted := *s
	if e = restarted.Check(ctx); e != nil {
		t.Fatal(e)
	}
	if _, e = restarted.Execute(ctx, req); e != nil {
		t.Fatal(e)
	}
	mutated := req
	mutated.Envelope.Resource = "b"
	mutated.Signature, _ = k["writer"].Sign(mutated.Envelope.Bytes(), ActionContext)
	if _, e = s.Execute(ctx, mutated); ErrorCode(e) != "CONFLICT" {
		t.Fatal(e)
	}
	// Revocation commits between challenge issuance and final protected operation.
	stale := prepareDB(t, s, k["writer"], "resource.transfer", "a", 2, map[string]any{"to": "b", "amount": 5, "to_version": 2})
	executeDB(t, s, k["admin"], "key.revoke", k["writer"].ID(), 0, struct{}{})
	if _, e = s.Execute(ctx, stale); ErrorCode(e) != "REVOKED" {
		t.Fatal(e)
	}
	if _, e = s.Execute(ctx, req); ErrorCode(e) != "REVOKED" {
		t.Fatal("cached result bypassed live authority", e)
	}
	if e = restarted.Check(ctx); e != nil {
		t.Fatal(e)
	}
}
func TestPostgresRacingRevocation(t *testing.T) {
	s, k := dbFixture(t)
	seedResources(t, s, k)
	ctx := context.Background()
	requests := make([]Request, 8)
	for i := range requests {
		requests[i] = prepareDB(t, s, k["writer"], "resource.transfer", "a", 1, map[string]any{"to": "b", "amount": 1, "to_version": 1})
	}
	revoke := prepareDB(t, s, k["admin"], "key.revoke", k["writer"].ID(), 0, struct{}{})
	start := make(chan struct{})
	var wg sync.WaitGroup
	for _, r := range requests {
		wg.Add(1)
		go func(req Request) {
			defer wg.Done()
			<-start
			_, e := s.Execute(ctx, req)
			if e != nil && ErrorCode(e) != "REVOKED" && ErrorCode(e) != "STALE_RESOURCE" {
				t.Error(e)
			}
		}(r)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, e := s.Execute(ctx, revoke); e != nil {
			t.Error(e)
		}
	}()
	close(start)
	wg.Wait()
	b, e := s.Export(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyBundle(b, s.Audit.Public, "test", nil); e != nil {
		t.Fatal(e)
	}
	revoked := false
	for _, raw := range b.Events {
		var event Event
		_ = json.Unmarshal(raw, &event)
		if event.Request == nil {
			continue
		}
		action := event.Request.Envelope.Action
		if action == "key.revoke" {
			revoked = true
		}
		if revoked && action == "resource.transfer" {
			t.Fatal("effect after revocation commit")
		}
	}
}
func TestPostgresRecoverySessionAndRollback(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	server := httptest.NewServer(Handler(s))
	defer server.Close()
	client, e := NewClient(server.URL, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	client.Protocol = 1 // This test retains the original v1 recovery/session contract.
	token, e := client.Session(k["admin"])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = client.State(token); e != nil {
		t.Fatal(e)
	}
	before, e := s.Export(ctx)
	if e != nil {
		t.Fatal(e)
	}
	executeDB(t, s, k["recovery1"], "subject.quarantine", "admin", 0, struct{}{})
	if _, e = client.State(token); e == nil {
		t.Fatal("revoked session still reads")
	}
	fresh := testKey(t, "admin")
	en := Enrollment{Subject: "admin", Role: "admin", Public: fresh.Public}
	en.Proof, _ = fresh.Sign(EnrollmentBytes(en), "KIG/enroll/v1")
	body := RecoveryBody{ID: "restore-admin", Expires: time.Now().Unix() + 600, Enrollment: en}
	for _, name := range []string{"recovery1", "recovery2"} {
		executeDB(t, s, k[name], "recovery.approve", "admin", 0, body)
	}
	if _, e = client.Session(k["admin"]); e == nil {
		t.Fatal("old key recovered")
	}
	if _, e = client.Session(fresh); e != nil {
		t.Fatal(e)
	}
	after, e := s.Export(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyBundle(before, s.Audit.Public, "test", &after.Checkpoint); e == nil {
		t.Fatal("stale restore")
	}
	anchorStore := *s
	anchorStore.Anchor = &after.Checkpoint
	if e = anchorStore.Check(ctx); e != nil {
		t.Fatal(e)
	}
	c, e := s.connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	if _, e = c.Exec(ctx, "DELETE FROM kig_events WHERE sequence >= $1", before.Checkpoint.Size); e != nil {
		t.Fatal(e)
	}
	if e = anchorStore.Check(ctx); e == nil {
		t.Fatal("rollback not quarantined")
	}
}
func TestHTTPBoundsOriginsTLSAndFailure(t *testing.T) {
	s, k := dbFixture(t)
	server := httptest.NewServer(Handler(s))
	defer server.Close()
	c, e := NewClient(server.URL, "test", "")
	if e != nil {
		t.Fatal(e)
	}
	c.Protocol = 1 // Legacy HTTP coverage; v2/migration have separate integration tests.
	if _, e = NewClient("http://192.0.2.1:8080", "test", ""); e == nil {
		t.Fatal("plaintext remote allowed")
	}
	for _, tc := range []struct {
		body, origin, content string
		status                int
	}{
		{`{"envelope":{},"envelope":{}}`, "", "application/json", 400},
		{`{}`, "https://evil.invalid", "application/json", 400},
		{`{}`, "", "text/plain", 400},
		{strings.Repeat("x", 2*MaxBody+1), "", "application/json", 400},
	} {
		req, _ := http.NewRequest("POST", server.URL+"/v1/actions", strings.NewReader(tc.body))
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Content-Type", tc.content)
		res, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatal(res.StatusCode)
		}
	}
	token, e := c.Session(k["observer"])
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.State(token); e != nil {
		t.Fatal(e)
	}
	b, e := c.Evidence(token)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = VerifyBundle(b, s.Audit.Public, "test", nil); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Prepare(k["observer"], "resource.create", "a", 0, []byte(`{"balance":1}`)); ErrorCode(e) != "POLICY_DENIED" {
		t.Fatal(e)
	}
	res, e := http.Get(server.URL + "/")
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Security-Policy") == "" {
		t.Fatal("dashboard security headers")
	}
}
func TestPostgresRollbackOnFailedSideEffect(t *testing.T) {
	s, k := dbFixture(t)
	ctx := context.Background()
	seedResources(t, s, k)
	r := prepareDB(t, s, k["writer"], "resource.transfer", "a", 1, map[string]any{"to": "b", "amount": 5, "to_version": 1})
	conn, e := s.connect(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close(ctx)
	_, e = conn.Exec(ctx, `CREATE FUNCTION reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected disk failure'; END $$; CREATE TRIGGER reject_audit BEFORE INSERT ON kig_events FOR EACH ROW EXECUTE FUNCTION reject_audit()`)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Execute(ctx, r); e == nil {
		t.Fatal("audit failure should abort effect")
	}
	if _, e = conn.Exec(ctx, "DROP TRIGGER reject_audit ON kig_events"); e != nil {
		t.Fatal(e)
	}
	// Same challenge remains usable because failed audit/effect/nonce changes rolled back together.
	if _, e = s.Execute(ctx, r); e != nil {
		t.Fatal(e)
	}
	if e = s.Check(ctx); e != nil {
		t.Fatal(e)
	}
}

func BenchmarkPostgresTransfer(b *testing.B) {
	s, k := dbFixture(b)
	seedResources(b, s, k)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		from, to := "a", "b"
		if i%2 == 1 {
			from, to = to, from
		}
		req := prepareDB(b, s, k["writer"], "resource.transfer", from, int64(i+1), map[string]any{"to": to, "amount": 1, "to_version": i + 1})
		if _, e := s.Execute(context.Background(), req); e != nil {
			b.Fatal(e)
		}
	}
}
func TestExpiredChallengeAndRoleChange(t *testing.T) {
	s, k := dbFixture(t)
	seedResources(t, s, k)
	ctx := context.Background()
	req := prepareDB(t, s, k["writer"], "resource.transfer", "a", 1, map[string]any{"to": "b", "amount": 1, "to_version": 1})
	executeDB(t, s, k["admin"], "subject.role", "writer", 0, map[string]string{"role": "auditor"})
	if _, e := s.Execute(ctx, req); ErrorCode(e) != "POLICY_DENIED" {
		t.Fatal(e)
	}
	raw := []byte(`{}`)
	id, _ := RandomID()
	expired, e := SignRequest(k["admin"], Envelope{Audience: "test", Action: "key.revoke", Resource: k["writer"].ID(), Operation: id, Expires: time.Now().Unix() - 1}, raw, ChallengeContext)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Issue(ctx, expired); ErrorCode(e) != "EXPIRED" {
		t.Fatal(e)
	}
	// An unrelated bound challenge cannot be substituted even with a valid signature.
	req = prepareDB(t, s, k["admin"], "resource.transfer", "a", 1, map[string]any{"to": "b", "amount": 1, "to_version": 1})
	req.Envelope.Resource = "b"
	req.Signature, _ = k["admin"].Sign(req.Envelope.Bytes(), ActionContext)
	if _, e = s.Execute(ctx, req); ErrorCode(e) != "CHALLENGE_MISMATCH" {
		t.Fatal(e)
	}
}
