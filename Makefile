.PHONY: build clean all test test-race vet lint

BINARY_NAME=azure-rbac-inventory
VERSION?=0.1.0
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# Default: build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY_NAME) .

# Build for all platforms
all: clean
	@mkdir -p dist
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe .
	GOOS=windows GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-arm64.exe .
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 .

test:
	go test ./... -v

test-race:
	go test -race ./... -count=1

vet:
	go vet ./...

lint:
	golangci-lint run ./...

checksums:
	@cd dist && sha256sum * > SHA256SUMS.txt

clean:
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	rm -rf dist/
