package spec

import "testing"

// Bounded abstraction of State.Apply: two replacement keys, two approvers,
// four approval attempts and one epoch-changing invalidation, in every order.
type recoveryState struct {
	Epoch, CurrentKey, Revoked, Used uint8
	ProposalEpoch, Approvals         [2]uint8
	Complete                         [2]bool
	StaleCommit                      bool
}

func recoveryStep(s recoveryState, action uint8, fence bool) recoveryState {
	s.Used |= 1 << action
	if action == 4 {
		s.Epoch++ // abstracts quarantine, key revocation or a role change
		return s
	}
	proposal, approver := action/2, action%2
	if s.Complete[proposal] || s.Approvals[proposal]&(1<<approver) != 0 {
		return s
	}
	if s.Approvals[proposal] == 0 {
		s.ProposalEpoch[proposal] = s.Epoch
	} else if fence && s.ProposalEpoch[proposal] != s.Epoch {
		return s
	}
	s.Approvals[proposal] |= 1 << approver
	if s.Approvals[proposal] == 3 {
		s.StaleCommit = s.StaleCommit || s.ProposalEpoch[proposal] != s.Epoch
		s.Revoked |= 1 << s.CurrentKey
		s.CurrentKey = proposal + 1
		s.Complete[proposal] = true
		s.Epoch++
	}
	return s
}

func exploreRecovery(t *testing.T, fence bool) (int, []uint8) {
	t.Helper()
	type entry struct {
		state recoveryState
		trace []uint8
	}
	queue := []entry{{state: recoveryState{Epoch: 1}}}
	seen := map[recoveryState]bool{}
	var counterexample []uint8
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]
		s := item.state
		if seen[s] {
			continue
		}
		seen[s] = true
		if s.StaleCommit && counterexample == nil {
			counterexample = item.trace
		}
		if s.Revoked&(1<<s.CurrentKey) != 0 {
			t.Fatal("reactivated a permanently revoked key", item.trace)
		}
		for action := uint8(0); action < 5; action++ {
			if s.Used&(1<<action) != 0 {
				continue
			}
			n := recoveryStep(s, action, fence)
			if s.Revoked&n.Revoked != s.Revoked {
				t.Fatal("revocation is not monotonic")
			}
			// A duplicate approver and a completed proposal cannot mutate authority.
			if action < 4 && recoveryStep(n, action, fence) != n {
				t.Fatal("approval is not idempotently rejected")
			}
			trace := append(append([]uint8(nil), item.trace...), action)
			queue = append(queue, entry{n, trace})
		}
	}
	return len(seen), counterexample
}

func TestRecoveryEpochModel(t *testing.T) {
	n, trace := exploreRecovery(t, true)
	if trace != nil {
		t.Fatal("epoch-fenced recovery accepted stale approvals", trace)
	}
	t.Logf("exhausted %d reachable epoch-fenced recovery states", n)
	n, trace = exploreRecovery(t, false)
	if trace == nil {
		t.Fatal("negative control failed to expose stale approval")
	}
	t.Logf("negative control: %d states; shortest counterexample %v (0=A0, 1=A1, 2=B0, 3=B1, 4=epoch change)", n, trace)
	// Explicitly check competing proposals independently of the invalidation event.
	s := recoveryState{Epoch: 1}
	for _, action := range []uint8{0, 2, 3, 1} {
		s = recoveryStep(s, action, false)
	}
	if !s.StaleCommit {
		t.Fatal("competing recovery negative control failed")
	}
}
