// Package guard implements Key Identity Guard's versioned protocol and authority.
package guard

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const Algorithm = "ML-DSA-65"
const MaxBody = 1 << 20
const ActionContext = "KIG/action/v1"
const ChallengeContext = "KIG/challenge/v1"
const Suite384 = "ML-DSA-65/SHA-384"

// Zero exists only in legacy state/genesis/checkpoints whose JSON omitted a version.
func protocolVersion(v int) int {
	if v == 0 {
		return 1
	}
	return v
}
func SignatureContext(kind string, version int) string {
	return fmt.Sprintf("KIG/%s/v%d", kind, protocolVersion(version))
}
func Digest(version int, b []byte) string {
	if version == 2 {
		h := sha512.Sum384(b)
		return hex.EncodeToString(h[:])
	}
	if version == 1 {
		return Hash(b)
	}
	return "" // Unknown suites never fall back to the legacy hash.
}

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

type KeyFile struct {
	Subject string `json:"subject"`
	Public  []byte `json:"public"`
	Private []byte `json:"private,omitempty"`
}

func NewKey(subject string) (KeyFile, error) {
	if !identifier.MatchString(subject) {
		return KeyFile{}, errors.New("invalid subject")
	}
	p, s, e := mldsa65.GenerateKey(rand.Reader)
	if e != nil {
		return KeyFile{}, e
	}
	return KeyFile{Subject: subject, Public: p.Bytes(), Private: s.Bytes()}, nil
}
func Hash(b []byte) string   { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (k KeyFile) ID() string { return Hash(k.Public) }
func (k KeyFile) Sign(b []byte, context string) (sig []byte, err error) {
	if len(k.Private) != mldsa65.PrivateKeySize {
		return nil, errors.New("invalid private key length")
	}
	if len(context) > 255 {
		return nil, errors.New("signature context exceeds 255 bytes")
	}
	// FIPS 204 skDecode assumes trusted input; CIRCL's decoder checks only length.
	if !bytes.Equal(k.Private[64:128], sha3.SumSHAKE256(k.Public, 64)) {
		return nil, errors.New("private key public hash mismatch")
	}
	for _, v := range k.Private[128:1536] { // (l+k)*256 eta=4 coefficients, two per byte.
		if v&15 > 8 || v>>4 > 8 {
			return nil, errors.New("private key coefficient out of range")
		}
	}
	var sk mldsa65.PrivateKey
	if err := sk.UnmarshalBinary(k.Private); err != nil {
		return nil, err
	}
	if !bytes.Equal(sk.Public().(*mldsa65.PublicKey).Bytes(), k.Public) {
		return nil, errors.New("key pair mismatch")
	}
	// A corrupt expanded key can exhaust CIRCL's bounded rejection loop and panic.
	defer func() {
		if recover() != nil {
			sig, err = nil, errors.New("ML-DSA signing failed")
		}
	}()
	sig = make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&sk, b, []byte(context), true, sig); err != nil {
		return nil, err
	}
	if !Verify(k.Public, b, sig, context) {
		return nil, errors.New("ML-DSA signature self-check failed")
	}
	return sig, nil
}
func Verify(public, b, sig []byte, context string) bool {
	if len(public) != mldsa65.PublicKeySize || len(sig) != mldsa65.SignatureSize {
		return false
	}
	var p mldsa65.PublicKey
	return p.UnmarshalBinary(public) == nil && mldsa65.Verify(&p, b, []byte(context), sig)
}
func RandomID() (string, error) {
	var b [32]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}

// Canonical signing uses a fixed field order and length prefixes, never JSON reserialization.
type Envelope struct {
	Version         int    `json:"version"`
	Suite           string `json:"suite,omitempty"`
	KeyCommitment   string `json:"key_commitment,omitempty"`
	Algorithm       string `json:"algorithm"`
	Subject         string `json:"subject"`
	KeyID           string `json:"key_id"`
	Audience        string `json:"audience"`
	Action          string `json:"action"`
	Resource        string `json:"resource"`
	ResourceVersion int64  `json:"resource_version"`
	BodyHash        string `json:"body_hash"`
	Challenge       string `json:"challenge"`
	Operation       string `json:"operation"`
	Expires         int64  `json:"expires"`
}
type Request struct {
	Envelope  Envelope `json:"envelope"`
	Body      []byte   `json:"body"`
	Signature []byte   `json:"signature"`
}

func fields(values ...string) []byte {
	var b bytes.Buffer
	for _, v := range values {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(v)))
		b.WriteString(v)
	}
	return b.Bytes()
}
func (e Envelope) Bytes() []byte {
	if e.Version == 2 {
		return fields("KIG/v2", "2", e.Suite, e.Algorithm, e.Subject, e.KeyID, e.KeyCommitment, e.Audience, e.Action, e.Resource,
			fmt.Sprint(e.ResourceVersion), e.BodyHash, e.Challenge, e.Operation, fmt.Sprint(e.Expires))
	}
	b := fields("KIG/v1", fmt.Sprint(e.Version), e.Algorithm, e.Subject, e.KeyID, e.Audience, e.Action, e.Resource,
		fmt.Sprint(e.ResourceVersion), e.BodyHash, e.Challenge, e.Operation, fmt.Sprint(e.Expires))
	return b
}
func (e Envelope) Intent() string { e.Challenge = ""; return Digest(e.Version, e.Bytes()) }
func (r Request) Digest() string  { return Digest(r.Envelope.Version, r.Envelope.Bytes()) }
func (r Request) Verify(public []byte, kind string) bool {
	return (r.Envelope.Version != 2 || r.Envelope.KeyCommitment == Digest(2, public)) &&
		Verify(public, r.Envelope.Bytes(), r.Signature, SignatureContext(kind, r.Envelope.Version))
}
func (r Request) Validate(audience string, challenge bool) error {
	e := r.Envelope
	if (e.Version != 1 && e.Version != 2) || e.Algorithm != Algorithm || e.Audience != audience || !identifier.MatchString(audience) {
		return errors.New("invalid protocol or audience")
	}
	if (e.Version == 1 && (e.Suite != "" || e.KeyCommitment != "")) ||
		(e.Version == 2 && (e.Suite != Suite384 || e.KeyCommitment != stringLowerHex(e.KeyCommitment, 48))) {
		return errors.New("invalid signature suite or key commitment")
	}
	for _, v := range []string{e.Subject, e.KeyID, e.Action, e.Resource, e.Operation} {
		if !identifier.MatchString(v) {
			return errors.New("invalid identifier")
		}
	}
	if e.ResourceVersion < 0 || e.Expires <= 0 || len(r.Body) == 0 || len(r.Body) > MaxBody || Digest(e.Version, r.Body) != e.BodyHash {
		return errors.New("invalid body or version")
	}
	digestSize := 32
	if e.Version == 2 {
		digestSize = 48
	}
	if e.KeyID != stringLowerHex(e.KeyID, 32) || e.BodyHash != stringLowerHex(e.BodyHash, digestSize) {
		return errors.New("invalid digest")
	}
	if challenge && e.Challenge != "" {
		return errors.New("unexpected challenge")
	}
	if !challenge && e.Challenge != stringLowerHex(e.Challenge, 32) {
		return errors.New("invalid challenge")
	}
	var value any
	if err := StrictJSON(r.Body, &value); err != nil {
		return err
	}
	if _, ok := value.(map[string]any); !ok {
		return errors.New("body must be object")
	}
	return nil
}
func stringLowerHex(s string, n int) string {
	b, e := hex.DecodeString(s)
	if e != nil || len(b) != n || hex.EncodeToString(b) != s {
		return "!"
	}
	return s
}
func SignRequest(k KeyFile, e Envelope, body []byte, context string) (Request, error) {
	if e.Version == 0 {
		e.Version = 1
	}
	if e.Version != 1 && e.Version != 2 {
		return Request{}, errors.New("unsupported protocol version")
	}
	if e.Version == 2 {
		e.Suite = Suite384
		e.KeyCommitment = Digest(2, k.Public)
	}
	e.Algorithm = Algorithm
	e.Subject = k.Subject
	e.KeyID = k.ID()
	e.BodyHash = Digest(e.Version, body)
	sig, err := k.Sign(e.Bytes(), context)
	return Request{e, body, sig}, err
}

// StrictJSON rejects duplicates at every depth, trailing values, invalid UTF-8 and unknown fields.
func StrictJSON(data []byte, out any) error {
	if !utf8.Valid(data) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var scan func(int) error
	scan = func(depth int) error {
		if depth > 32 {
			return errors.New("JSON nesting limit")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return err
					}
					s, ok := key.(string)
					if !ok || seen[s] {
						return errors.New("duplicate object key")
					}
					seen[s] = true
					if err = scan(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return errors.New("invalid object")
				}
			case '[':
				for d.More() {
					if err := scan(depth + 1); err != nil {
						return err
					}
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return errors.New("invalid array")
				}
			default:
				return errors.New("invalid delimiter")
			}
		}
		return nil
	}
	if err := scan(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	if out == nil || reflect.TypeOf(out).Kind() != reflect.Pointer {
		return errors.New("JSON target must be a pointer")
	}
	if e := jsonShape(data, reflect.TypeOf(out).Elem()); e != nil {
		return e
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	d.UseNumber()
	return d.Decode(out)
}
func validPublic(b []byte) bool {
	if len(b) != mldsa65.PublicKeySize {
		return false
	}
	var p mldsa65.PublicKey
	return p.UnmarshalBinary(b) == nil
}

func operationKey(e Envelope) string       { return Digest(e.Version, fields(e.Subject, e.Operation)) }
func legacyOperationKey(e Envelope) string { return Hash(fields(e.Subject, e.Operation)) }
