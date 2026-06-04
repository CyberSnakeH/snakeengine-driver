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

.PHONY: all clean install test

all: $(BIN)

$(BIN): main.go go.mod go.sum
	$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $@ .

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)

test:
	$(GO) test ./...

clean:
	rm -f $(BIN)
