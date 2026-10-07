GO ?= go
OUT ?= churro-gen

.PHONY: all build test loader-assets clean

all: build

# The generator itself does not use cgo. Native loader images are checked in.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -o $(OUT) ./cmd/churro-gen

test:
	$(GO) test ./...

# Requires Zig 0.17.0 to build the native Windows loader assets.
loader-assets:
	./scripts/rebuild-loader-blobs.sh

clean:
	rm -f $(OUT)
