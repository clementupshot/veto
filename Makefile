.PHONY: build test vet tidy clean install install-preload codegen-deps generate-mocks interposer

BIN := veto
PKG := ./cmd/veto

INTERPOSER_SRC := internal/interposer/veto_interpose.c

# Per-OS shared library output. The .dylib/.so name is referenced from
# install-preload.go — keep both sides in sync.
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
	INTERPOSER_OUT := libveto_interpose.dylib
	# On Apple Silicon, system shells like /bin/sh and /bin/bash are
	# built for arm64e (Apple's pointer-auth ABI variant). When the
	# spawner exec's such a shell, dyld in the child process tries to
	# load DYLD_INSERT_LIBRARIES and refuses any non-arm64e dylib. We
	# build a fat dylib so the same artifact loads into both arches.
	ifeq ($(UNAME_M),arm64)
		INTERPOSER_CFLAGS := -O2 -Wall -Wextra -fno-common -dynamiclib -arch arm64 -arch arm64e
	else
		INTERPOSER_CFLAGS := -O2 -Wall -Wextra -fno-common -dynamiclib
	endif
else
	INTERPOSER_OUT := libveto_interpose.so
	INTERPOSER_CFLAGS := -O2 -Wall -Wextra -fPIC -shared
endif

build:
	go build -trimpath -ldflags="-s -w" -o $(BIN) $(PKG)

test:
	go test -race ./...

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BIN) coverage.out coverage.html $(INTERPOSER_OUT)

install: build
	install -m 0755 $(BIN) $(HOME)/.local/bin/$(BIN)

# `make interposer` builds the native shared library that intercepts
# execve/posix_spawn for direct-child-process coverage. See
# internal/interposer/veto_interpose.c for the design rationale and
# `veto install-preload` for installation.
interposer: $(INTERPOSER_OUT)

$(INTERPOSER_OUT): $(INTERPOSER_SRC)
	$(CC) $(INTERPOSER_CFLAGS) -o $@ $<

install-preload: interposer build
	./$(BIN) install-preload --lib $(PWD)/$(INTERPOSER_OUT)

codegen-deps:
	go install github.com/vektra/mockery/v3@latest

generate-mocks:
	mockery
