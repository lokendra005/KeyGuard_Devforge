package guard

import "errors"

// Upgrade binds the original v1 checkpoint and a SHA-384 commitment to the same
// exact history bytes. Its outer request is signed with the v2 suite and context.
type Upgrade struct {
	Version     int        `json:"version"`
	Suite       string     `json:"suite"`
	Previous    Checkpoint `json:"previous"`
	HistoryRoot string     `json:"history_root"`
}

func PrepareUpgrade(b Bundle, public []byte, audience string, anchor *Checkpoint) (Upgrade, error) {
	s, err := VerifyBundle(b, public, audience, anchor)
	if err != nil {
		return Upgrade{}, err
	}
	if s.Version() != 1 || b.Checkpoint.Version != 0 {
		return Upgrade{}, errors.New("upgrade requires v1 history")
	}
	root, err := RootForVersion(b.Events, 2)
	return Upgrade{Version: 2, Suite: Suite384, Previous: b.Checkpoint, HistoryRoot: root}, err
}

func (u Upgrade) VerifyPrefix(events [][]byte, public []byte, audience string) error {
	if u.Version != 2 || u.Suite != Suite384 || u.Previous.Version != 0 || !u.Previous.Valid(public, audience) || u.Previous.Size != int64(len(events)) {
		return fail("INVALID_UPGRADE")
	}
	old, err := RootForVersion(events, 1)
	if err != nil || old != u.Previous.Root {
		return fail("INVALID_UPGRADE")
	}
	next, err := RootForVersion(events, 2)
	if err != nil || next != u.HistoryRoot {
		return fail("INVALID_UPGRADE")
	}
	return nil
}
