package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

type Fault struct {
	Code string `json:"code"`
}

func (f *Fault) Error() string { return f.Code }
func fail(code string) error   { return &Fault{code} }
func ErrorCode(e error) string {
	var f *Fault
	if errors.As(e, &f) {
		return f.Code
	}
	return "INTERNAL"
}

type Member struct {
	Role   string `json:"role"`
	Active bool   `json:"active"`
	Epoch  int64  `json:"epoch"`
}
type RegisteredKey struct {
	Subject string `json:"subject"`
	Public  []byte `json:"public"`
	Revoked bool   `json:"revoked"`
}
type Resource struct {
	Balance int64 `json:"balance"`
	Version int64 `json:"version"`
}
type Challenge struct {
	Intent  string `json:"intent"`
	Expires int64  `json:"expires"`
}
type Session struct {
	Subject string `json:"subject"`
	KeyID   string `json:"key_id"`
	Expires int64  `json:"expires"`
}
type Recovery struct {
	Epoch     int64    `json:"epoch,omitempty"`
	Digest    string   `json:"digest"`
	Approvers []string `json:"approvers"`
	Complete  bool     `json:"complete"`
	Expires   int64    `json:"expires"`
}
type Operation struct {
	Digest string `json:"digest"`
	Result Result `json:"result"`
}
type State struct {
	ProtocolVersion int                      `json:"protocol_version,omitempty"`
	LastTime        int64                    `json:"last_time"`
	Members         map[string]Member        `json:"members"`
	Keys            map[string]RegisteredKey `json:"keys"`
	Resources       map[string]Resource      `json:"resources"`
	Challenges      map[string]Challenge     `json:"challenges"`
	Sessions        map[string]Session       `json:"sessions"`
	Recoveries      map[string]Recovery      `json:"recoveries"`
	Operations      map[string]Operation     `json:"operations"`
	Sequence        int64                    `json:"sequence"`
}
type Identity struct {
	Subject string `json:"subject"`
	Role    string `json:"role"`
	Public  []byte `json:"public"`
}
type Genesis struct {
	Version    int        `json:"version,omitempty"`
	Suite      string     `json:"suite,omitempty"`
	Audience   string     `json:"audience"`
	Identities []Identity `json:"identities"`
}
type Result struct {
	Operation string `json:"operation"`
	Sequence  int64  `json:"sequence"`
	Message   string `json:"message"`
}
type Enrollment struct {
	Version int    `json:"version,omitempty"`
	Subject string `json:"subject"`
	Role    string `json:"role"`
	Public  []byte `json:"public"`
	Proof   []byte `json:"proof"`
}

func EnrollmentBytes(e Enrollment) []byte {
	if e.Version == 2 {
		return fields("KIG/enrollment/v2", Suite384, e.Subject, e.Role, string(e.Public))
	}
	return fields("KIG/enrollment/v1", e.Subject, e.Role, string(e.Public))
}

type RecoveryBody struct {
	ID         string     `json:"id"`
	Expires    int64      `json:"expires"`
	Enrollment Enrollment `json:"enrollment"`
}

func NewState(g Genesis) (State, error) {
	s := State{Members: map[string]Member{}, Keys: map[string]RegisteredKey{}, Resources: map[string]Resource{}, Challenges: map[string]Challenge{}, Sessions: map[string]Session{}, Recoveries: map[string]Recovery{}, Operations: map[string]Operation{}}
	if (g.Version != 0 && g.Version != 2) || (g.Version == 0 && g.Suite != "") || (g.Version == 2 && g.Suite != Suite384) {
		return s, errors.New("unsupported genesis suite")
	}
	s.ProtocolVersion = g.Version
	if !identifier.MatchString(g.Audience) {
		return s, errors.New("invalid audience")
	}
	counts := map[string]int{}
	for _, i := range g.Identities {
		if !identifier.MatchString(i.Subject) || !validRole(i.Role) || len(i.Public) == 0 {
			return s, errors.New("invalid identity")
		}
		if _, exists := s.Members[i.Subject]; exists {
			return s, errors.New("duplicate subject")
		}
		if _, exists := s.Keys[Hash(i.Public)]; exists {
			return s, errors.New("duplicate key")
		}
		if !validPublic(i.Public) {
			return s, errors.New("invalid public key")
		}
		s.Members[i.Subject] = Member{i.Role, true, 1}
		s.Keys[Hash(i.Public)] = RegisteredKey{i.Subject, i.Public, false}
		counts[i.Role]++
	}
	if counts["admin"] < 1 || counts["recovery"] < 2 {
		return s, errors.New("genesis needs admin and two distinct recovery identities")
	}
	return s, nil
}
func validRole(r string) bool {
	return r == "admin" || r == "writer" || r == "auditor" || r == "recovery"
}
func (s *State) Actor(e Envelope) (Member, error) {
	k, ok := s.Keys[e.KeyID]
	m, exists := s.Members[e.Subject]
	if !ok || !exists || k.Subject != e.Subject {
		return m, fail("UNKNOWN_IDENTITY")
	}
	if k.Revoked || !m.Active {
		return m, fail("REVOKED")
	}
	return m, nil
}
func (s *State) Allowed(e Envelope) error {
	m, err := s.Actor(e)
	if err != nil {
		return err
	}
	allowed := false
	switch e.Action {
	case "session.create":
		allowed = true
	case "resource.create", "key.enroll", "subject.role", "protocol.upgrade":
		allowed = m.Role == "admin"
	case "resource.transfer":
		allowed = m.Role == "writer" || m.Role == "admin"
	case "key.revoke", "subject.quarantine":
		allowed = m.Role == "admin" || m.Role == "recovery"
	case "recovery.approve":
		allowed = m.Role == "recovery"
	default:
		return fail("UNKNOWN_ACTION")
	}
	if !allowed {
		return fail("POLICY_DENIED")
	}
	return nil
}
func validateEnrollment(e Enrollment, version int) error {
	if (e.Version != 0 && e.Version != 2) || protocolVersion(e.Version) != version || !identifier.MatchString(e.Subject) || !validRole(e.Role) || !Verify(e.Public, EnrollmentBytes(e), e.Proof, SignatureContext("enroll", e.Version)) {
		return fail("INVALID_ENROLLMENT")
	}
	return nil
}
func decodeBody(raw []byte, v any) error {
	if StrictJSON(raw, v) != nil {
		return fail("INVALID_BODY")
	}
	return nil
}

const MaxBalance int64 = 1_000_000_000_000

// Apply contains every protected side effect. Call only under the authority transaction.
// Replay calls the same transition function after independently verifying event signatures.
func (s *State) Apply(r Request, now int64) (Result, error) {
	e := r.Envelope
	if err := s.ProtocolAllowed(e); err != nil {
		return Result{}, err
	}
	if now < s.LastTime {
		return Result{}, fail("CLOCK_REGRESSION")
	}
	if e.Action != "resource.transfer" && e.ResourceVersion != 0 {
		return Result{}, fail("INVALID_BODY")
	}
	if err := s.Allowed(e); err != nil {
		return Result{}, err
	}
	result := Result{e.Operation, s.Sequence + 1, "committed"}
	switch e.Action {
	case "protocol.upgrade":
		var b Upgrade
		if err := decodeBody(r.Body, &b); err != nil {
			return result, err
		}
		if s.Version() != 1 || e.Version != 2 || e.Resource != "protocol" || b.Version != 2 || b.Suite != Suite384 || b.Previous.Size != s.Sequence+1 || b.HistoryRoot != stringLowerHex(b.HistoryRoot, 48) {
			return result, fail("INVALID_UPGRADE")
		}
		// The store and offline replay verify the signed checkpoint and actual prefix.
		s.ProtocolVersion = 2
		s.Challenges = map[string]Challenge{}
		s.Sessions = map[string]Session{}
		for id, rec := range s.Recoveries {
			if !rec.Complete {
				delete(s.Recoveries, id)
			}
		}
		for id, member := range s.Members {
			member.Epoch++
			s.Members[id] = member
		}
		result.Message = "upgraded_to_v2"
	case "session.create":
		if e.Resource != e.Subject {
			return result, fail("INVALID_BODY")
		}
		var b struct {
			TokenHash string `json:"token_hash"`
		}
		if err := decodeBody(r.Body, &b); err != nil {
			return result, err
		}
		n := 32
		if e.Version == 2 {
			n = 48
		}
		if b.TokenHash != stringLowerHex(b.TokenHash, n) {
			return result, fail("INVALID_BODY")
		}
		if _, exists := s.Sessions[b.TokenHash]; exists {
			return result, fail("CONFLICT")
		}
		for k, v := range s.Sessions {
			if v.Expires <= now {
				delete(s.Sessions, k)
			}
		}
		if len(s.Sessions) >= 1000 {
			return result, fail("CAPACITY")
		}
		s.Sessions[b.TokenHash] = Session{e.Subject, e.KeyID, now + 1800}
	case "resource.create":
		var b struct {
			Balance int64 `json:"balance"`
		}
		if err := decodeBody(r.Body, &b); err != nil {
			return result, err
		}
		if b.Balance < 0 || b.Balance > MaxBalance || e.ResourceVersion != 0 {
			return result, fail("INVALID_BODY")
		}
		if _, exists := s.Resources[e.Resource]; exists {
			return result, fail("CONFLICT")
		}
		s.Resources[e.Resource] = Resource{b.Balance, 1}
	case "resource.transfer":
		var b struct {
			To        string `json:"to"`
			Amount    int64  `json:"amount"`
			ToVersion int64  `json:"to_version"`
		}
		if err := decodeBody(r.Body, &b); err != nil {
			return result, err
		}
		from, ok := s.Resources[e.Resource]
		to, exists := s.Resources[b.To]
		if !ok || !exists || b.To == e.Resource || b.Amount <= 0 || b.Amount > MaxBalance {
			return result, fail("INVALID_TRANSFER")
		}
		if from.Version != e.ResourceVersion || to.Version != b.ToVersion {
			return result, fail("STALE_RESOURCE")
		}
		if from.Balance < b.Amount || to.Balance > MaxBalance-b.Amount {
			return result, fail("BALANCE_LIMIT")
		}
		from.Balance -= b.Amount
		to.Balance += b.Amount
		from.Version++
		to.Version++
		s.Resources[e.Resource] = from
		s.Resources[b.To] = to
	case "key.enroll":
		var b Enrollment
		if err := decodeBody(r.Body, &b); err != nil {
			return result, err
		}
		if err := validateEnrollment(b, e.Version); err != nil {
			return result, err
		}
		if b.Subject != e.Resource || (b.Role != "writer" && b.Role != "auditor") {
			return result, fail("POLICY_DENIED")
		}
		if _, ok := s.Members[b.Subject]; ok {
			return result, fail("CONFLICT")
		}
		if _, ok := s.Keys[Hash(b.Public)]; ok {
			return result, fail("CONFLICT")
		}
		s.Members[b.Subject] = Member{b.Role, true, 1}
		s.Keys[Hash(b.Public)] = RegisteredKey{b.Subject, b.Public, false}
	case "key.revoke":
		var b struct{}
		if err := decodeBody(r.Body, &b); err != nil {
			return result, err
		}
		key, ok := s.Keys[e.Resource]
		if !ok {
			return result, fail("NOT_FOUND")
		}
		if key.Revoked {
			return result, fail("ALREADY_REVOKED")
		}
		if s.Members[key.Subject].Role == "recovery" {
			return result, fail("RECOVERY_PROTECTED")
		}
		key.Revoked = true
		s.Keys[e.Resource] = key
		m := s.Members[key.Subject]
		m.Epoch++
		s.Members[key.Subject] = m
	case "subject.quarantine":
		var b struct{}
		if err := decodeBody(r.Body, &b); err != nil {
			return result, err
		}
		m, ok := s.Members[e.Resource]
		if !ok {
			return result, fail("NOT_FOUND")
		}
		if m.Role == "recovery" {
			return result, fail("RECOVERY_PROTECTED")
		}
		if !m.Active {
			return result, fail("ALREADY_REVOKED")
		}
		m.Active = false
		m.Epoch++
		s.Members[e.Resource] = m
	case "subject.role":
		var b struct {
			Role string `json:"role"`
		}
		if err := decodeBody(r.Body, &b); err != nil {
			return result, err
		}
		m, ok := s.Members[e.Resource]
		if !ok {
			return result, fail("NOT_FOUND")
		}
		if (b.Role != "writer" && b.Role != "auditor") || (m.Role != "writer" && m.Role != "auditor") {
			return result, fail("POLICY_DENIED")
		}
		m.Role = b.Role
		m.Epoch++
		s.Members[e.Resource] = m
	case "recovery.approve":
		var b RecoveryBody
		if err := decodeBody(r.Body, &b); err != nil {
			return result, err
		}
		if err := validateEnrollment(b.Enrollment, e.Version); err != nil {
			return result, err
		}
		old, ok := s.Members[b.Enrollment.Subject]
		if !ok || old.Role == "recovery" || old.Role != b.Enrollment.Role || e.Resource != b.Enrollment.Subject || !identifier.MatchString(b.ID) || b.Expires <= now || b.Expires > now+3600 {
			return result, fail("INVALID_RECOVERY")
		}
		if _, ok := s.Keys[Hash(b.Enrollment.Public)]; ok {
			return result, fail("KEY_REUSE")
		}
		canonical, _ := json.Marshal(b)
		digest := Digest(e.Version, canonical)
		rec, exists := s.Recoveries[b.ID]
		if exists && (rec.Digest != digest || rec.Complete || rec.Epoch != old.Epoch) {
			return result, fail("CONFLICT")
		}
		for _, actor := range rec.Approvers {
			if actor == e.Subject {
				return result, fail("DUPLICATE_APPROVER")
			}
			m := s.Members[actor]
			if !m.Active || m.Role != "recovery" {
				return result, fail("INVALID_RECOVERY")
			}
		}
		rec.Epoch = old.Epoch
		rec.Digest = digest
		rec.Expires = b.Expires
		rec.Approvers = append(rec.Approvers, e.Subject)
		if len(rec.Approvers) == 2 {
			for id, k := range s.Keys {
				if k.Subject == e.Resource {
					k.Revoked = true
					s.Keys[id] = k
				}
			}
			old.Active = true
			old.Epoch++
			s.Members[e.Resource] = old
			s.Keys[Hash(b.Enrollment.Public)] = RegisteredKey{e.Resource, b.Enrollment.Public, false}
			rec.Complete = true
			result.Message = "recovered"
		} else {
			result.Message = "awaiting_second_approval"
		}
		s.Recoveries[b.ID] = rec
	}
	s.Sequence++
	s.LastTime = now
	return result, nil
}
func (s State) Summary() map[string]any {
	identities := []map[string]any{}
	for id, k := range s.Keys {
		m := s.Members[k.Subject]
		identities = append(identities, map[string]any{"key_id": id, "subject": k.Subject, "role": m.Role, "active": m.Active && !k.Revoked, "epoch": m.Epoch})
	}
	sort.Slice(identities, func(i, j int) bool {
		return fmt.Sprint(identities[i]["subject"]) < fmt.Sprint(identities[j]["subject"])
	})
	return map[string]any{"protocol_version": s.Version(), "identities": identities, "resources": s.Resources, "sequence": s.Sequence, "recoveries": s.Recoveries}
}

func (s State) Version() int { return protocolVersion(s.ProtocolVersion) }
func (s State) ProtocolAllowed(e Envelope) error {
	if s.Version() != 1 && s.Version() != 2 {
		return fail("STATE_CORRUPT")
	}
	if s.Version() == 1 && e.Action == "protocol.upgrade" && e.Version == 2 {
		return nil
	}
	if e.Version != s.Version() {
		return fail("PROTOCOL_VERSION")
	}
	return nil
}
