package diem

// Event is a protocol event. The set is closed: the unexported method means no
// other package can add a member, so the dispatch switch in Core is exhaustive
// by construction and needs no default case. It is the paper's
// start_event_processing, typed.
type Event interface{ event() }

// ProposalEvent is an authenticated proposal from another replica, or from
// this one through the transport's local node.
type ProposalEvent struct{ Msg *ProposalMsg }

// VoteEvent is an authenticated vote addressed to this replica as the next
// round's leader.
type VoteEvent struct{ Msg *VoteMsg }

// TimeoutEvent is an authenticated timeout from another replica.
type TimeoutEvent struct{ Msg *TimeoutMsg }

// LocalTimeoutEvent is this replica's own round timer firing.
type LocalTimeoutEvent struct{ Round Round }

func (ProposalEvent) event()     {}
func (VoteEvent) event()         {}
func (TimeoutEvent) event()      {}
func (LocalTimeoutEvent) event() {}

// Queue is the inbound event queue: bounded and blocking, so a producer waits
// rather than an accepted event being dropped.
type Queue chan Event

// NewQueue returns a queue of the given capacity.
func NewQueue(size int) Queue { return make(Queue, size) }

// Push blocks when the queue is full. It never drops.
func (q Queue) Push(e Event) { q <- e }
