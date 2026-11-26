package guard

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

//go:embed schema.sql
var schema string

// Store deliberately uses a short-lived connection per operation. The authority
// lock, not a process mutex, serializes writers across independent server processes.
type Store struct {
	DSN        string
	Audience   string
	Audit      KeyFile
	Anchor     *Checkpoint
	MinVersion int
}

func (s *Store) connect(ctx context.Context) (*pgx.Conn, error) { return pgx.Connect(ctx, s.DSN) }
func (s *Store) Migrate(ctx context.Context) error {
	c, e := s.connect(ctx)
	if e != nil {
		return e
	}
	defer c.Close(ctx)
	_, e = c.Exec(ctx, schema)
	if e != nil {
		return e
	}
	var exists bool
	if e = c.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='kig_app')").Scan(&exists); e != nil {
		return e
	}
	if exists {
		_, e = c.Exec(ctx, "GRANT SELECT,INSERT,UPDATE ON kig_authority TO kig_app; GRANT SELECT,INSERT ON kig_events TO kig_app; REVOKE UPDATE,DELETE,TRUNCATE ON kig_events FROM kig_app")
	}
	return e
}
func (s *Store) Init(ctx context.Context, g Genesis) error {
	state, e := NewState(g)
	if e != nil {
		return e
	}
	if g.Audience != s.Audience {
		return errors.New("audience mismatch")
	}
	c, e := s.connect(ctx)
	if e != nil {
		return e
	}
	defer c.Close(ctx)
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT set_config('kig.protocol_version','2',true)"); e != nil {
		return e
	}
	data, e := marshal(state)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO kig_authority(id,audience,audit_key,state,schema_version) VALUES(1,$1,$2,$3,$4)", s.Audience, s.Audit.Public, data, state.Version())
	if e != nil {
		return e
	}
	var now int64
	if e = tx.QueryRow(ctx, "SELECT floor(extract(epoch from clock_timestamp()))::bigint").Scan(&now); e != nil {
		return e
	}
	state.LastTime = now
	data, e = marshal(state)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE kig_authority SET state=$1 WHERE id=1", data); e != nil {
		return e
	}
	event, e := marshal(Event{Sequence: 0, Time: now, Genesis: &g})
	if e != nil {
		return e
	}
	if _, e = RootForVersion([][]byte{event}, state.Version()); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "INSERT INTO kig_events(sequence,payload) VALUES(0,$1)", event); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (s *Store) transaction(ctx context.Context, fn func(pgx.Tx, *State, int64) error) error {
	c, e := s.connect(ctx)
	if e != nil {
		return fail("AUTHORITY_UNAVAILABLE")
	}
	defer c.Close(context.Background())
	tx, e := c.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if e != nil {
		return fail("AUTHORITY_UNAVAILABLE")
	}
	defer tx.Rollback(context.Background())
	var data, key []byte
	var audience string
	var schemaVersion int
	// The single authority row is the serialization point for all protected effects.
	e = tx.QueryRow(ctx, "SELECT state,audience,audit_key,schema_version FROM kig_authority WHERE id=1 FOR UPDATE").Scan(&data, &audience, &key, &schemaVersion)
	if e != nil {
		return fail("AUTHORITY_UNAVAILABLE")
	}
	if audience != s.Audience || !bytes.Equal(key, s.Audit.Public) {
		return fail("TRUST_MISMATCH")
	}
	var state State
	if json.Unmarshal(data, &state) != nil {
		return fail("STATE_CORRUPT")
	}
	if state.Version() != schemaVersion || (schemaVersion != 1 && schemaVersion != 2) {
		return fail("STATE_CORRUPT")
	}
	if schemaVersion < protocolVersion(s.MinVersion) {
		return fail("PROTOCOL_VERSION")
	}
	if _, e = tx.Exec(ctx, "SELECT set_config('kig.protocol_version','2',true)"); e != nil {
		return e
	}

	if s.Anchor != nil {
		rows, err := tx.Query(ctx, "SELECT payload FROM kig_events WHERE sequence < $1 ORDER BY sequence", s.Anchor.Size)
		if err != nil {
			return err
		}
		var history [][]byte
		for rows.Next() {
			var b []byte
			if err = rows.Scan(&b); err != nil {
				rows.Close()
				return err
			}
			history = append(history, b)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		root, err := RootForVersion(history, protocolVersion(s.Anchor.Version))
		if !s.Anchor.Valid(s.Audit.Public, s.Audience) || schemaVersion < protocolVersion(s.Anchor.Version) || err != nil || int64(len(history)) != s.Anchor.Size || root != s.Anchor.Root {
			return fail("RESTORE_QUARANTINE")
		}
	}
	var now int64
	if e = tx.QueryRow(ctx, "SELECT floor(extract(epoch from clock_timestamp()))::bigint").Scan(&now); e != nil {
		return e
	}
	if now < state.LastTime {
		return fail("CLOCK_REGRESSION")
	}
	if e = fn(tx, &state, now); e != nil {
		return e
	}
	state.LastTime = now
	data, e = marshal(state)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "UPDATE kig_authority SET state=$1,schema_version=$2 WHERE id=1", data, state.Version()); e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return fail("OUTCOME_UNKNOWN")
	}
	return nil
}
func (s *Store) Issue(ctx context.Context, r Request) (ChallengeReply, error) {
	var reply ChallengeReply
	if err := r.Validate(s.Audience, true); err != nil {
		return reply, fail("INVALID_REQUEST")
	}
	err := s.transaction(ctx, func(tx pgx.Tx, st *State, now int64) error {
		if err := st.ProtocolAllowed(r.Envelope); err != nil {
			return err
		}
		if r.Envelope.Action == "protocol.upgrade" && st.Version() != 1 {
			return fail("PROTOCOL_VERSION")
		}
		if st.Sequence >= MaxEvents-1 {
			return fail("CAPACITY")
		}
		if err := st.Allowed(r.Envelope); err != nil {
			return err
		}
		key := st.Keys[r.Envelope.KeyID]
		if !r.Verify(key.Public, "challenge") {
			return fail("INVALID_SIGNATURE")
		}
		if r.Envelope.Expires <= now || r.Envelope.Expires > now+120 {
			return fail("EXPIRED")
		}
		for id, c := range st.Challenges {
			if c.Expires <= now {
				delete(st.Challenges, id)
			}
		}
		if len(st.Challenges) >= 4096 {
			return fail("CAPACITY")
		}
		id, e := RandomID()
		if e != nil {
			return e
		}
		st.Challenges[id] = Challenge{r.Envelope.Intent(), r.Envelope.Expires}
		reply = ChallengeReply{id, r.Envelope.Expires}
		return nil
	})
	return reply, err
}

type ChallengeReply struct {
	Challenge string `json:"challenge"`
	Expires   int64  `json:"expires"`
}

func (s *Store) Execute(ctx context.Context, r Request) (Result, error) {
	var result Result
	if r.Validate(s.Audience, false) != nil {
		return result, fail("INVALID_REQUEST")
	}
	err := s.transaction(ctx, func(tx pgx.Tx, st *State, now int64) error {
		if err := st.ProtocolAllowed(r.Envelope); err != nil {
			return err
		}
		if err := st.Allowed(r.Envelope); err != nil {
			return err
		}
		key := st.Keys[r.Envelope.KeyID]
		if !r.Verify(key.Public, "action") {
			return fail("INVALID_SIGNATURE")
		}
		op := operationKey(r.Envelope)
		if old, ok := st.Operations[op]; ok {
			if old.Digest != r.Digest() {
				return fail("CONFLICT")
			}
			result = old.Result
			return nil
		}
		if r.Envelope.Version == 2 {
			if _, exists := st.Operations[legacyOperationKey(r.Envelope)]; exists {
				return fail("CONFLICT")
			}
		}
		if st.Sequence >= MaxEvents-1 {
			return fail("CAPACITY")
		}
		if r.Envelope.Expires <= now {
			return fail("EXPIRED")
		}
		challenge, ok := st.Challenges[r.Envelope.Challenge]
		if !ok {
			return fail("REPLAY")
		}
		if challenge.Intent != r.Envelope.Intent() || challenge.Expires != r.Envelope.Expires {
			return fail("CHALLENGE_MISMATCH")
		}
		if r.Envelope.Action == "protocol.upgrade" {
			var u Upgrade
			if StrictJSON(r.Body, &u) != nil {
				return fail("INVALID_UPGRADE")
			}
			history, err := readHistory(ctx, tx)
			if err != nil {
				return err
			}
			if err = u.VerifyPrefix(history, s.Audit.Public, s.Audience); err != nil {
				return err
			}
		}
		var err error
		result, err = st.Apply(r, now)
		if err != nil {
			return err
		}
		delete(st.Challenges, r.Envelope.Challenge)
		st.Operations[op] = Operation{r.Digest(), result}
		event, err := marshal(Event{Sequence: st.Sequence, Time: now, Request: &r, Result: &result})
		if err != nil {
			return err
		}
		var storedBytes int64
		if err = tx.QueryRow(ctx, "SELECT COALESCE(sum(octet_length(payload)),0)::bigint FROM kig_events").Scan(&storedBytes); err != nil {
			return err
		}
		if len(event) > 2*MaxBody || storedBytes+int64(len(event)) > MaxAuditBytes {
			return fail("CAPACITY")
		}
		_, err = tx.Exec(ctx, "INSERT INTO kig_events(sequence,payload) VALUES($1,$2)", st.Sequence, event)
		return err
	})
	return result, err
}
func (s *Store) ReadSession(ctx context.Context, token string) (map[string]any, error) {
	var summary map[string]any
	err := s.transaction(ctx, func(tx pgx.Tx, st *State, now int64) error {
		ses, err := sessionAllowed(st, token, now)
		if err != nil {
			return err
		}
		summary = st.Summary()
		summary["audience"] = s.Audience
		summary["session_subject"] = ses.Subject
		summary["session_expires"] = ses.Expires
		return nil
	})
	return summary, err
}
func (s *Store) Export(ctx context.Context) (Bundle, error) {
	c, e := s.connect(ctx)
	if e != nil {
		return Bundle{}, e
	}
	defer c.Close(ctx)
	rows, e := c.Query(ctx, "SELECT payload FROM kig_events ORDER BY sequence LIMIT $1", MaxEvents+1)
	if e != nil {
		return Bundle{}, e
	}
	defer rows.Close()
	var events [][]byte
	for rows.Next() {
		var b []byte
		if e = rows.Scan(&b); e != nil {
			return Bundle{}, e
		}
		events = append(events, b)
	}
	if rows.Err() != nil {
		return Bundle{}, rows.Err()
	}
	return SignBundle(events, s.Audience, s.Audit)
}
func (s *Store) Check(ctx context.Context) error {
	if s.MinVersion != 0 && s.MinVersion != 1 && s.MinVersion != 2 {
		return errors.New("unsupported minimum protocol")
	}
	if s.Anchor != nil && !s.Anchor.Valid(s.Audit.Public, s.Audience) {
		return errors.New("invalid configured anchor")
	}
	b, e := s.Export(ctx)
	if e != nil {
		return e
	}
	verified, e := VerifyBundle(b, s.Audit.Public, s.Audience, s.Anchor)
	if e != nil {
		return e
	}
	// Compare replayable authority fields, including sessions. Challenge issuance is not audited.
	return s.transaction(ctx, func(tx pgx.Tx, st *State, now int64) error {
		if st.Sequence != verified.Sequence {
			return fmt.Errorf("authority changed during startup check; retry startup")
		}
		// Legacy proposals have no epoch. They stay unusable for new approvals;
		// ignoring only this absent metadata preserves verification of old valid history.
		for id, rec := range st.Recoveries {
			if rec.Epoch == 0 {
				if v, ok := verified.Recoveries[id]; ok {
					v.Epoch = 0
					verified.Recoveries[id] = v
				}
			}
		}
		a, _ := marshal([]any{st.Version(), st.Members, st.Keys, st.Resources, st.Recoveries, st.Operations, st.Sessions})
		v, _ := marshal([]any{verified.Version(), verified.Members, verified.Keys, verified.Resources, verified.Recoveries, verified.Operations, verified.Sessions})
		if !bytes.Equal(a, v) {
			return errors.New("authority state disagrees with audited history")
		}
		return nil
	})
}
func Deadline() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 15*time.Second)
}

func sessionAllowed(st *State, token string, now int64) (Session, error) {
	ses, ok := st.Sessions[Digest(st.Version(), []byte(token))]
	if !ok || ses.Expires <= now {
		return ses, fail("UNAUTHORIZED")
	}
	m, err := st.Actor(Envelope{Subject: ses.Subject, KeyID: ses.KeyID})
	if err != nil {
		return ses, fail("UNAUTHORIZED")
	}
	if m.Role != "admin" && m.Role != "auditor" && m.Role != "recovery" {
		return ses, fail("POLICY_DENIED")
	}
	return ses, nil
}
func (s *Store) ExportSession(ctx context.Context, token string) (Bundle, error) {
	var history [][]byte
	err := s.transaction(ctx, func(tx pgx.Tx, st *State, now int64) error {
		if _, err := sessionAllowed(st, token, now); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, "SELECT payload FROM kig_events ORDER BY sequence LIMIT $1", MaxEvents+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b []byte
			if err = rows.Scan(&b); err != nil {
				return err
			}
			history = append(history, b)
		}
		return rows.Err()
	})
	if err != nil {
		return Bundle{}, err
	}
	return SignBundle(history, s.Audience, s.Audit)
}
func (s *Store) Ready(ctx context.Context) error {
	return s.transaction(ctx, func(pgx.Tx, *State, int64) error { return nil })
}

func readHistory(ctx context.Context, tx pgx.Tx) ([][]byte, error) {
	rows, err := tx.Query(ctx, "SELECT payload FROM kig_events ORDER BY sequence LIMIT $1", MaxEvents+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var history [][]byte
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		history = append(history, b)
	}
	return history, rows.Err()
}
