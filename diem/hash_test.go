package diem

import "testing"

// TestDomainSeparation checks that the domain tag actually separates the four
// digest functions and the block id: fed correspondingly-shaped zero inputs,
// none of them may collide.
func TestDomainSeparation(t *testing.T) {
	digests := map[string]Hash{
		"VoteInfoHash":       VoteInfoHash(VoteInfo{}),
		"LedgerCommitDigest": LedgerCommitDigest(LedgerCommitInfo{}),
		"TimeoutDigest":      TimeoutDigest(0, 0),
		"ExecuteHash":        ExecuteHash(Hash{}, nil),
		"blockID":            blockID(0, 0, nil, &QC{}),
	}

	seen := make(map[Hash]string, len(digests))
	for name, d := range digests {
		if other, ok := seen[d]; ok {
			t.Errorf("%s and %s produced the same digest: %x", name, other, d)
			continue
		}
		seen[d] = name
	}
}

func TestVoteInfoFieldSensitivity(t *testing.T) {
	base := VoteInfo{
		ID:          Hash{1},
		Round:       1,
		ParentID:    Hash{2},
		ParentRound: 2,
		ExecStateID: Hash{3},
	}
	baseHash := VoteInfoHash(base)

	tests := []struct {
		name string
		v    VoteInfo
	}{
		{"ID", VoteInfo{ID: Hash{9}, Round: base.Round, ParentID: base.ParentID, ParentRound: base.ParentRound, ExecStateID: base.ExecStateID}},
		{"Round", VoteInfo{ID: base.ID, Round: 9, ParentID: base.ParentID, ParentRound: base.ParentRound, ExecStateID: base.ExecStateID}},
		{"ParentID", VoteInfo{ID: base.ID, Round: base.Round, ParentID: Hash{9}, ParentRound: base.ParentRound, ExecStateID: base.ExecStateID}},
		{"ParentRound", VoteInfo{ID: base.ID, Round: base.Round, ParentID: base.ParentID, ParentRound: 9, ExecStateID: base.ExecStateID}},
		{"ExecStateID", VoteInfo{ID: base.ID, Round: base.Round, ParentID: base.ParentID, ParentRound: base.ParentRound, ExecStateID: Hash{9}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := VoteInfoHash(tt.v); got == baseHash {
				t.Errorf("changing %s left VoteInfoHash unchanged", tt.name)
			}
		})
	}
}

func TestLedgerCommitInfoFieldSensitivity(t *testing.T) {
	base := LedgerCommitInfo{CommitStateID: Hash{1}, VoteInfoHash: Hash{2}}
	baseHash := LedgerCommitDigest(base)

	tests := []struct {
		name string
		l    LedgerCommitInfo
	}{
		{"CommitStateID", LedgerCommitInfo{CommitStateID: Hash{9}, VoteInfoHash: base.VoteInfoHash}},
		{"VoteInfoHash", LedgerCommitInfo{CommitStateID: base.CommitStateID, VoteInfoHash: Hash{9}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := LedgerCommitDigest(tt.l); got == baseHash {
				t.Errorf("changing %s left LedgerCommitDigest unchanged", tt.name)
			}
		})
	}
}

func TestBlockFieldSensitivity(t *testing.T) {
	baseQC := &QC{VoteInfo: VoteInfo{ID: Hash{7}}}
	otherQC := &QC{VoteInfo: VoteInfo{ID: Hash{8}}}
	basePayload := [][]byte{[]byte("payload")}

	base := blockID(1, 1, basePayload, baseQC)

	tests := []struct {
		name string
		id   Hash
	}{
		{"author", blockID(2, 1, basePayload, baseQC)},
		{"round", blockID(1, 2, basePayload, baseQC)},
		{"payload", blockID(1, 1, [][]byte{[]byte("other")}, baseQC)},
		{"qc", blockID(1, 1, basePayload, otherQC)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.id == base {
				t.Errorf("changing %s left the block id unchanged", tt.name)
			}
		})
	}
}

// TestBlockIDCoversQCSignatures is the paper's
// hash(author || round || payload || qc.vote_info.id || qc.signatures):
// two otherwise identical blocks over differently-signed QCs must not collide.
func TestBlockIDCoversQCSignatures(t *testing.T) {
	qc1 := &QC{VoteInfo: VoteInfo{ID: Hash{1}}, Signatures: []Signature{{Signer: 1, Data: []byte("a")}}}
	qc2 := &QC{VoteInfo: VoteInfo{ID: Hash{1}}, Signatures: []Signature{{Signer: 2, Data: []byte("b")}}}

	id1 := blockID(1, 1, [][]byte{[]byte("x")}, qc1)
	id2 := blockID(1, 1, [][]byte{[]byte("x")}, qc2)
	if id1 == id2 {
		t.Error("blocks differing only in qc.Signatures produced the same id")
	}
}

func TestExecuteHashDeterministic(t *testing.T) {
	prev := Hash{1}
	payload := [][]byte{[]byte("a"), []byte("b")}
	if ExecuteHash(prev, payload) != ExecuteHash(prev, payload) {
		t.Error("ExecuteHash is not deterministic")
	}
}

func TestExecuteHashOrderSensitive(t *testing.T) {
	prev := Hash{1}
	h1 := ExecuteHash(prev, [][]byte{[]byte("a"), []byte("b")})
	h2 := ExecuteHash(prev, [][]byte{[]byte("b"), []byte("a")})
	if h1 == h2 {
		t.Error("ExecuteHash is not sensitive to payload order")
	}
}
