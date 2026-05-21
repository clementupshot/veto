.PHONY: build test vet tidy clean install codegen-deps generate-mocks

BIN := bouncer
PKG := ./cmd/bouncer

build:
	go build -trimpath -ldflags="-s -w" -o $(BIN) $(PKG)

test:
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BIN) coverage.out coverage.html

install: build
	install -m 0755 $(BIN) $(HOME)/.local/bin/$(BIN)

codegen-deps:
	go install github.com/vektra/mockery/v3@latest

generate-mocks:
	mockery
