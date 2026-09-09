package hotstuff

// Event is a protocol event. The set is closed: the unexported method means no
// other package can add a member, so the dispatch switch in consensus is
// exhaustive by construction and needs no default case.
type Event interface{ event() }

// ProposeEvent is an authenticated proposal from the leader of its block's view.
type ProposeEvent struct{ Proposal }

// VoteEvent is an authenticated vote addressed to this replica.
type VoteEvent struct{ PartialCert }

// TimeoutEvent is an authenticated timeout from another replica.
type TimeoutEvent struct{ TimeoutMsg }

// FetchedEvent carries a block backfilled by Transport.Fetch. The transport has
// already checked that the block hashes to what was asked for.
type FetchedEvent struct{ Block *Block }

// ViewTimeoutEvent is this replica's own view timer firing.
type ViewTimeoutEvent struct{ View View }

func (ProposeEvent) event()     {}
func (VoteEvent) event()        {}
func (TimeoutEvent) event()     {}
func (FetchedEvent) event()     {}
func (ViewTimeoutEvent) event() {}

// Queue is the inbound event queue: bounded and blocking, so a producer waits
// rather than an accepted event being dropped.
type Queue chan Event

func NewQueue(size int) Queue { return make(Queue, size) }

// Push blocks when the queue is full. It never drops.
func (q Queue) Push(e Event) { q <- e }
