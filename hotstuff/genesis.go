package hotstuff

// genesis is the one immutable genesis block every replica hardcodes
// identically: view 0, zero parent, zero QC, proposer 0, no commands.
var genesis = NewBlock(Hash{}, 0, 0, QuorumCert{}, nil)

// Genesis returns the same immutable block every call.
func Genesis() *Block { return genesis }

// GenesisHash is the genesis block's hash.
func GenesisHash() Hash { return genesis.Hash() }
