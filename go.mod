module github.com/DanyGoT/HotStuffs

go 1.26.2

// Gorums is pinned to a commit, not a tag: the API this code targets lives on
// the cmd/sweep branch and differs from released v0.11.0 (no QuorumSpec, free
// function clients). A branch-derived pseudo-version means a stray `go get -u`
// would silently move off commit 1077e6c, so keep this require line exact.
require github.com/relab/gorums v0.11.1-0.20260812123016-1077e6cd0466 // indirect

require (
	github.com/google/go-cmp v0.7.0 // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.38.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260630182238-925bb5da69e7 // indirect
	google.golang.org/grpc v1.82.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

tool (
	github.com/relab/gorums/cmd/protoc-gen-gorums
	google.golang.org/protobuf/cmd/protoc-gen-go
)
