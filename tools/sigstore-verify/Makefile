# Makefile for sigstore-verify.
#
#   make             → build statically-linked, stripped binary
#   make VERSION=x.y → embed version string
#   make install     → install to $(PREFIX)/bin/sigstore-verify
#   make clean

GO       ?= go
PREFIX   ?= /usr/local
DESTDIR  ?=
VERSION  ?= dev
BIN      := sigstore-verify

GOFLAGS  := -trimpath -buildvcs=false
LDFLAGS  := -s -w -X main.version=$(VERSION)

# CGO_ENABLED=0 → fully static binary, no glibc dependency.
export CGO_ENABLED=0

.PHONY: all clean install test FORCE

all: $(BIN)

$(BIN): main.go go.mod go.sum FORCE
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $@ .

# VERSION is embedded by the linker; changing it must refresh an existing binary.
FORCE:

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

test:
	$(GO) test ./...

clean:
	rm -f $(BIN)
