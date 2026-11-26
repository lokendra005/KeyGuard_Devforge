package guard

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"
)

const MaxEvents = 100000

// Base64-wrapped history stays below the 64 MiB CLI/HTTP verification limit.
const MaxAuditBytes int64 = 32 << 20
const CheckpointContext = "KIG/checkpoint/v1"
const WitnessContext = "KIG/witness/v1"

type Event struct {
	Sequence int64    `json:"sequence"`
	Time     int64    `json:"time"`
	Genesis  *Genesis `json:"genesis,omitempty"`
	Request  *Request `json:"request,omitempty"`
	Result   *Result  `json:"result,omitempty"`
}
type Checkpoint struct {
	Version   int    `json:"version,omitempty"`
	Suite     string `json:"suite,omitempty"`
	Audience  string `json:"audience"`
	Size      int64  `json:"size"`
	Root      string `json:"root"`
	Signature []byte `json:"signature"`
}

func (c Checkpoint) Bytes() []byte {
	if c.Version == 2 {
		return fields("KIG/checkpoint/v2", Suite384, c.Audience, fmt.Sprint(c.Size), c.Root)
	}
	return fields("KIG/checkpoint/v1", c.Audience, fmt.Sprint(c.Size), c.Root)
}
func (c Checkpoint) Context() string        { return SignatureContext("checkpoint", c.Version) }
func (c Checkpoint) WitnessContext() string { return SignatureContext("witness", c.Version) }
func (c Checkpoint) Valid(public []byte, audience string) bool {
	n := 32
	if c.Version == 2 {
		n = 48
	}
	return (c.Version == 0 && c.Suite == "" || c.Version == 2 && c.Suite == Suite384) &&
		c.Audience == audience && c.Size >= 1 && c.Size <= MaxEvents && c.Root == stringLowerHex(c.Root, n) && Verify(public, c.Bytes(), c.Signature, c.Context())
}

type Bundle struct {
	Events     [][]byte   `json:"events"`
	Checkpoint Checkpoint `json:"checkpoint"`
}
type WitnessReceipt struct {
	Checkpoint Checkpoint `json:"checkpoint"`
	Signature  []byte     `json:"signature"`
}

func Root(events [][]byte) (string, error) {
	return RootForVersion(events, 1)
}
func RootForVersion(events [][]byte, version int) (string, error) {
	if version != 1 && version != 2 {
		return "", errors.New("unsupported tree version")
	}
	if len(events) == 0 || len(events) > MaxEvents {
		return "", errors.New("invalid event count")
	}
	var total int64
	for _, event := range events {
		total += int64(len(event))
		if len(event) > 2*MaxBody || total > MaxAuditBytes {
			return "", errors.New("audit byte capacity exceeded")
		}
	}
	h := rfc6962.DefaultHasher
	if version == 2 {
		h = rfc6962.New(crypto.SHA384)
	}
	f := compact.RangeFactory{Hash: h.HashChildren}
	r := f.NewEmptyRange(0)
	for _, e := range events {
		if err := r.Append(h.HashLeaf(e), nil); err != nil {
			return "", err
		}
	}
	b, err := r.GetRootHash(nil)
	return hex.EncodeToString(b), err
}
func SignBundle(events [][]byte, audience string, k KeyFile) (Bundle, error) {
	// Preserve original events; only the checkpoint/tree suite advances at cutover.
	version := 1
	if len(events) == 0 || len(events) > MaxEvents {
		return Bundle{}, errors.New("invalid event count")
	}
	var total int64
	for _, raw := range events {
		total += int64(len(raw))
		if len(raw) > 2*MaxBody || total > MaxAuditBytes {
			return Bundle{}, errors.New("audit byte capacity exceeded")
		}
		var e Event
		if err := StrictJSON(raw, &e); err != nil {
			return Bundle{}, err
		}
		if e.Genesis != nil {
			version = protocolVersion(e.Genesis.Version)
		}
		if e.Request != nil && e.Request.Envelope.Action == "protocol.upgrade" {
			version = 2
		}
	}
	root, err := RootForVersion(events, version)
	if err != nil {
		return Bundle{}, err
	}
	c := Checkpoint{Audience: audience, Size: int64(len(events)), Root: root}
	if version == 2 {
		c.Version = 2
		c.Suite = Suite384
	}
	c.Signature, err = k.Sign(c.Bytes(), c.Context())
	return Bundle{events, c}, err
}

// VerifyBundle replays signed transitions and verifies the complete RFC6962 tree.
// Trust is supplied by the caller, never by the bundle being verified.
func VerifyBundle(b Bundle, public []byte, audience string, anchor *Checkpoint) (State, error) {
	c := b.Checkpoint
	if c.Size != int64(len(b.Events)) || !c.Valid(public, audience) {
		return State{}, errors.New("invalid checkpoint")
	}
	root, err := RootForVersion(b.Events, protocolVersion(c.Version))
	if err != nil || root != c.Root {
		return State{}, errors.New("invalid Merkle root")
	}
	if anchor != nil {
		if anchor.Size > c.Size || protocolVersion(anchor.Version) > protocolVersion(c.Version) || !anchor.Valid(public, audience) {
			return State{}, errors.New("invalid or newer anchor")
		}
		prefix, err := RootForVersion(b.Events[:int(anchor.Size)], protocolVersion(anchor.Version))
		if err != nil || prefix != anchor.Root {
			return State{}, errors.New("history rollback or fork")
		}
	}
	var state State
	var lastTime int64
	used := map[string]bool{}
	for i, raw := range b.Events {
		if len(raw) > 2*MaxBody {
			return State{}, errors.New("oversized event")
		}
		var e Event
		if err := StrictJSON(raw, &e); err != nil {
			return State{}, err
		}
		if e.Sequence != int64(i) || e.Time <= 0 || e.Time < lastTime {
			return State{}, errors.New("invalid sequence or time")
		}
		lastTime = e.Time
		if i == 0 {
			if e.Genesis == nil || e.Request != nil || e.Result != nil || e.Genesis.Audience != audience {
				return State{}, errors.New("invalid genesis")
			}
			state, err = NewState(*e.Genesis)
			state.LastTime = e.Time
			if err != nil {
				return State{}, err
			}
			continue
		}
		if e.Genesis != nil || e.Request == nil || e.Result == nil {
			return State{}, errors.New("invalid action event")
		}
		r := *e.Request
		k, ok := state.Keys[r.Envelope.KeyID]
		if r.Validate(audience, false) != nil || !ok || !r.Verify(k.Public, "action") || r.Envelope.Expires <= e.Time || state.ProtocolAllowed(r.Envelope) != nil {
			return State{}, errors.New("invalid event signature or expiry")
		}
		op := operationKey(r.Envelope)
		if r.Envelope.Version == 2 {
			if _, exists := state.Operations[legacyOperationKey(r.Envelope)]; exists {
				return State{}, errors.New("operation already executed in v1")
			}
		}
		if _, ok := state.Operations[op]; ok || used[r.Envelope.Challenge] {
			return State{}, errors.New("replayed event")
		}
		if r.Envelope.Action == "protocol.upgrade" {
			var u Upgrade
			if StrictJSON(r.Body, &u) != nil || u.VerifyPrefix(b.Events[:i], public, audience) != nil {
				return State{}, errors.New("invalid upgrade history commitment")
			}
		}
		result, err := state.Apply(r, e.Time)
		if err != nil {
			return State{}, fmt.Errorf("event %d: %w", i, err)
		}
		if result != *e.Result {
			return State{}, errors.New("incorrect event result")
		}
		used[r.Envelope.Challenge] = true
		state.Operations[op] = Operation{r.Digest(), result}
	}
	if state.Version() != protocolVersion(c.Version) {
		return State{}, errors.New("checkpoint protocol downgrade or mismatch")
	}
	return state, nil
}
func Attest(b Bundle, public []byte, audience string, previous *WitnessReceipt, witness KeyFile) (WitnessReceipt, error) {
	var anchor *Checkpoint
	if previous != nil {
		if !Verify(witness.Public, previous.Checkpoint.Bytes(), previous.Signature, previous.Checkpoint.WitnessContext()) {
			return WitnessReceipt{}, errors.New("invalid retained witness state")
		}
		anchor = &previous.Checkpoint
	}
	if _, err := VerifyBundle(b, public, audience, anchor); err != nil {
		return WitnessReceipt{}, err
	}
	sig, err := witness.Sign(b.Checkpoint.Bytes(), b.Checkpoint.WitnessContext())
	return WitnessReceipt{b.Checkpoint, sig}, err
}
func marshal(v any) ([]byte, error) { return json.Marshal(v) }
