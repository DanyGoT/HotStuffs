package hotstuff

// ID identifies a replica.
type ID uint32

// View is a consensus view number.
type View uint64

// Hash is a SHA-256 digest.
type Hash [32]byte

// Signature. Signer is a *claim*: it means nothing until the signature verifies
// against the public key registered for that ID.
type Signature struct {
	Signer ID
	Data   []byte
}

// QuorumCert is self-authenticating: a receiver verifies it without trusting
// whoever forwarded it.
type QuorumCert struct {
	View      View
	BlockHash Hash
	Sigs      []Signature
}

// TimeoutCert aggregates a quorum of timeout votes for a view.
type TimeoutCert struct {
	View View
	Sigs []Signature
}

// PartialCert is one replica's vote for a block.
type PartialCert struct {
	View      View
	BlockHash Hash
	Sig       Signature
}

// Proposal is a leader's block, signed, optionally carrying the TimeoutCert
// that justified entering the block's view.
type Proposal struct {
	Block *Block
	Sig   Signature
	TC    *TimeoutCert
}

// TimeoutMsg reports that its sender gave up on View. The signature covers only
// the view, so timeouts aggregate into a TimeoutCert; HighQC authenticates
// itself.
type TimeoutMsg struct {
	View   View
	Sig    Signature
	HighQC QuorumCert
}

// SyncInfo is the evidence permitting entry to a view: a QC for the previous
// view on the happy path, or a TC for it after a timeout.
type SyncInfo struct {
	QC QuorumCert
	TC *TimeoutCert // nil on the happy path
}

// View is the view this evidence permits entry to.
func (si SyncInfo) View() View {
	v := si.QC.View
	if si.TC != nil && si.TC.View > v {
		v = si.TC.View
	}
	return v + 1
}

// State is the read-only scalar snapshot handed to Rules.
type State struct {
	View, LastVotedView, LockedView, CommittedView View
	HighQC                                         QuorumCert
}
