GO ?= go
OUT ?= churro-gen

.PHONY: all build test clean

all: build

# The generator itself does not use cgo. The checked-in loader blobs were built
# by Fritter's MinGW build and are already embedded by the Go package.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(OUT) ./cmd/churro-gen

test:
	$(GO) test ./...

clean:
	rm -f $(OUT)
