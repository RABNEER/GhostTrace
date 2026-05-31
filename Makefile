.PHONY: all build test vet lint clean install

all: build

build:
	$(MAKE) -C asm
	$(MAKE) -C cshim
	CGO_ENABLED=1 go build -ldflags="-s -w" -o bin/ghosttrace ./cmd/ghosttrace

test:
	$(MAKE) -C asm
	$(MAKE) -C cshim
	CGO_ENABLED=1 go test ./... -race -count=1

vet:
	go vet ./...

lint:
	golangci-lint run ./...

install:
	bash scripts/install.sh

clean:
	$(MAKE) -C asm clean
	$(MAKE) -C cshim clean
	rm -rf bin/
