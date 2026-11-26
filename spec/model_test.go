package spec

import "testing"

// The state graph models all interleavings of one signed action and one revocation.
// It proves only this finite model; the SQL integration tests establish correspondence.
type state struct {
	Writer, Revoker, Lock               int
	Revoked, Allowed, Effect, Violation bool
}

func successors(s state, guarded bool) []state {
	out := []state{}
	add := func(n state) { out = append(out, n) }
	switch s.Writer {
	case 0:
		n := s
		n.Writer = 1
		n.Allowed = !s.Revoked
		add(n) // initial authentication
	case 1:
		if !guarded || s.Lock == 0 {
			n := s
			n.Writer = 2
			if guarded {
				n.Lock = 1
				n.Allowed = !s.Revoked
			}
			add(n)
		}
	case 2:
		n := s
		n.Writer = 3
		if n.Allowed {
			n.Effect = true
			n.Violation = n.Revoked
		}
		if guarded {
			n.Lock = 0
		}
		add(n)
	}
	switch s.Revoker {
	case 0:
		if !guarded || s.Lock == 0 {
			n := s
			n.Revoker = 1
			if guarded {
				n.Lock = 2
			}
			add(n)
		}
	case 1:
		n := s
		n.Revoker = 2
		n.Revoked = true
		if guarded {
			n.Lock = 0
		}
		add(n)
	}
	return out
}
func explore(guarded bool) (int, bool) {
	seen := map[state]bool{}
	queue := []state{{}}
	violation := false
	for len(queue) > 0 {
		s := queue[0]
		queue = queue[1:]
		if seen[s] {
			continue
		}
		seen[s] = true
		violation = violation || s.Violation
		queue = append(queue, successors(s, guarded)...)
	}
	return len(seen), violation
}
func TestRevocationModel(t *testing.T) {
	n, bad := explore(true)
	if bad {
		t.Fatal("guarded model violates safety")
	}
	t.Logf("exhausted %d reachable guarded states", n)
	n, bad = explore(false)
	if !bad {
		t.Fatal("negative control failed to expose stale authorization race")
	}
	t.Logf("negative control exposes race across %d states", n)
}
