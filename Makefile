GO_DIRS := diem crypto diemnet replica cmd
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
# A dot in the first path element means a domain, i.e. not stdlib.
DOMAIN := ^[^/]*\.
DIEM_OK := ^google.golang.org/\|^github.com/relab/gorums\|^github.com/DanyGoT/HotStuffs/proto/

check-deps:
	@! go list -f '{{join .Imports "\n"}}' ./diem | grep '$(DOMAIN)' | grep -v '$(DIEM_OK)' | grep .
	@! go list -f '{{join .Deps "\n"}}' ./crypto | grep '$(DOMAIN)' | grep .
	@! grep -rEq --include='*.go' '^[[:space:]]*go ' diem
	@! grep -rq --include='*.go' 'reflect\.' $(GO_DIRS)
	@echo "check-deps: ok"

clean:
	rm -rf $(BIN)
