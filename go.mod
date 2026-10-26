module github.com/DanyGoT/HotStuffs

go 1.27.3

require (
	github.com/relab/gorums v0.12.0
	github.com/relab/gorums/benchkit v0.12.0
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	golang.org/x/exp v0.0.0-20261014143641-f0251eb4aa3e // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.61.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261019180522-ce908d29299b // indirect
)

tool (
	github.com/relab/gorums/cmd/protoc-gen-gorums
	google.golang.org/protobuf/cmd/protoc-gen-go
)
