GO_DIRS := hotstuff crypto blockchain consensus network simnet replica cmd
PROTO   := proto/hotstuffpb/hotstuff.proto
BIN     := $(CURDIR)/bin
PLUGINS := $(BIN)/protoc-gen-go $(BIN)/protoc-gen-gorums

.PHONY: all proto build test race check-deps tools clean

all: build test

tools $(PLUGINS): go.mod
	GOBIN=$(BIN) go install tool

# The file argument must be relative to an include root, so "." is one of them.
proto: $(PLUGINS)
	PATH="$(BIN):$$PATH" protoc \
	  -I="$(shell go list -m -f '{{.Dir}}' github.com/relab/gorums):." \
	  --go_out=paths=source_relative:. \
	  --go_opt=default_api_level=API_OPAQUE \
	  --gorums_out=paths=source_relative:. \
	  $(PROTO)

build:
	go build ./...

test:
	go test ./...

race:
	go test -race ./...

# The dependency direction, enforced mechanically rather than by discipline.
check-deps:
	@! go list -f '{{join .Deps "\n"}}' ./hotstuff | grep -q '\.'
	@! grep -rq --include='*.go' 'hotstuffpb\|relab/gorums' $(wildcard hotstuff crypto blockchain consensus) /dev/null
	@! grep -rEq --include='*.go' '^[[:space:]]*go ' $(wildcard hotstuff consensus) /dev/null
	@! grep -rq --include='*.go' 'reflect\.' $(wildcard $(GO_DIRS)) /dev/null
	@echo "check-deps: ok"

clean:
	rm -rf $(BIN)
