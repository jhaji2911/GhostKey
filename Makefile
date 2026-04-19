VERSION ?= v0.1.3
LDFLAGS := -ldflags="-s -w -X main.Version=$(VERSION)"

.PHONY: build test lint release install-ca clean

build:
	go build $(LDFLAGS) -o bin/ghostkey ./cmd/ghostkey

test:
	go test -race -coverprofile=coverage.out ./...

lint:
	golangci-lint run

release:
	mkdir -p dist
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o dist/ghostkey-linux-amd64    ./cmd/ghostkey
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o dist/ghostkey-linux-arm64    ./cmd/ghostkey
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o dist/ghostkey-darwin-amd64   ./cmd/ghostkey
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o dist/ghostkey-darwin-arm64   ./cmd/ghostkey
	GOOS=windows GOARCH=amd64  go build $(LDFLAGS) -o dist/ghostkey-windows-amd64.exe ./cmd/ghostkey
	cd dist && sha256sum ghostkey-* > SHA256SUMS

install-ca:
	./scripts/install-ca.sh

clean:
	rm -rf bin/ dist/ coverage.out
