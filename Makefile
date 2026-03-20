.PHONY: build clean all test test-race

BINARY_NAME=azure-rbac-inventory
VERSION?=0.1.0
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION)"

# Default: build for current platform
build:
	go build $(LDFLAGS) -o $(BINARY_NAME).exe .

# Build for all platforms
all: windows-amd64 windows-arm64 linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

windows-amd64:
	set GOOS=windows&& set GOARCH=amd64&& go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-amd64.exe .

windows-arm64:
	set GOOS=windows&& set GOARCH=arm64&& go build $(LDFLAGS) -o dist/$(BINARY_NAME)-windows-arm64.exe .

linux-amd64:
	set GOOS=linux&& set GOARCH=amd64&& go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-amd64 .

linux-arm64:
	set GOOS=linux&& set GOARCH=arm64&& go build $(LDFLAGS) -o dist/$(BINARY_NAME)-linux-arm64 .

darwin-amd64:
	set GOOS=darwin&& set GOARCH=amd64&& go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-amd64 .

darwin-arm64:
	set GOOS=darwin&& set GOARCH=arm64&& go build $(LDFLAGS) -o dist/$(BINARY_NAME)-darwin-arm64 .

test:
	go test ./... -v

test-race:
	go test -race ./... -count=1

vet:
	go vet ./...

clean:
	if exist $(BINARY_NAME).exe del $(BINARY_NAME).exe
	if exist dist rmdir /s /q dist
