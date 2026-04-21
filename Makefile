# Auto-detect version from the current git tag; fall back to a default.
# Override on the command line:  make release VERSION=v1.2.3
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null || git describe --tags --abbrev=0 2>/dev/null || echo v0.1.4)

# -s -w       → strip symbol table / DWARF (smaller binary)
# -X ...      → bake the version string in at link time
LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION)"

# -trimpath removes local file-system paths from the binary (reproducible builds).
# CGO_ENABLED=0 produces a fully-static binary.
# This is REQUIRED so install.sh works on Alpine, old glibc systems, minimal
# Docker containers, and any host that doesn't have the exact libc version the
# CI runner used.
BUILDFLAGS := -trimpath
export CGO_ENABLED=0

.PHONY: build test lint release install-ca clean

build:
	go build $(BUILDFLAGS) $(LDFLAGS) -o bin/ghostkey ./cmd/ghostkey

test:
	go test -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run

release:
	mkdir -p dist
	GOOS=linux   GOARCH=amd64  go build $(BUILDFLAGS) $(LDFLAGS) -o dist/ghostkey-linux-amd64      ./cmd/ghostkey
	GOOS=linux   GOARCH=arm64  go build $(BUILDFLAGS) $(LDFLAGS) -o dist/ghostkey-linux-arm64      ./cmd/ghostkey
	GOOS=darwin  GOARCH=amd64  go build $(BUILDFLAGS) $(LDFLAGS) -o dist/ghostkey-darwin-amd64     ./cmd/ghostkey
	GOOS=darwin  GOARCH=arm64  go build $(BUILDFLAGS) $(LDFLAGS) -o dist/ghostkey-darwin-arm64     ./cmd/ghostkey
	GOOS=windows GOARCH=amd64  go build $(BUILDFLAGS) $(LDFLAGS) -o dist/ghostkey-windows-amd64.exe ./cmd/ghostkey
	cd dist && sha256sum ghostkey-linux-* ghostkey-darwin-* ghostkey-windows-* > SHA256SUMS

install-ca:
	./scripts/install-ca.sh

clean:
	rm -rf bin/ dist/ coverage.out
