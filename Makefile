PROTO   := proto/diempb/diem.proto
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
	  --gorums_out=paths=source_relative:. \
	  $(PROTO)

build:
	go build ./...

test:
	go test ./...

race:
	go test -race ./...

# The protocol core runs on one goroutine; concurrency lives outside diem.
check-deps:
	@! grep -rEq --include='*.go' '^[[:space:]]*go ' diem
	@echo "check-deps: ok"

clean:
	rm -rf $(BIN)
