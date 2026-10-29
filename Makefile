# rdpshot build automation. POSIX make compatible.

GO      ?= go
DOCKER  ?= docker
VERSION ?= dev

BINARY  = bin/rdpshot
LDFLAGS = -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt lint cross docker clean

all: build

build:
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/rdpshot

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

lint:
	@unformatted="$$(gofmt -l .)"; \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt required for:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi
	$(GO) vet ./...

cross:
	GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/rdpshot-linux-amd64 ./cmd/rdpshot
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/rdpshot-linux-arm64 ./cmd/rdpshot
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/rdpshot-windows-amd64.exe ./cmd/rdpshot
	GOOS=windows GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/rdpshot-windows-arm64.exe ./cmd/rdpshot
	GOOS=darwin GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/rdpshot-darwin-amd64 ./cmd/rdpshot
	GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/rdpshot-darwin-arm64 ./cmd/rdpshot

docker:
	$(DOCKER) build --target slim --build-arg VERSION=$(VERSION) -t rdpshot:$(VERSION) .
	$(DOCKER) build --target full --build-arg VERSION=$(VERSION) -t rdpshot:$(VERSION)-full .

clean:
	rm -rf bin