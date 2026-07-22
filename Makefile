.PHONY: all check fmt fmt-check vet build windows test e2e run binary dist

# The library is pure Go. Forcing CGO off keeps every build identical across
# hosts and sidesteps broken toolchains (e.g. windows-11-arm runners ship an
# x86_64 gcc that can't assemble runtime/cgo's arm64 stubs). CGO off also
# makes the cmd/libtunnel launcher a static, dependency-free binary that runs
# on a scratch/distroless base.
export CGO_ENABLED = 0

# Release build inputs for the cmd/libtunnel launcher.
#   VERSION  — stamped into the binary (`libtunnel version`); git describe by
#              default, overridable (the release workflow passes the tag).
#   GO_LDFLAGS — strip the symbol table (-s) and DWARF (-w) for a smaller
#                binary; -trimpath (on the build lines) drops host paths so
#                the build is reproducible.
#   PLATFORMS — the release OS/arch matrix.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO_LDFLAGS = -s -w -X main.version=$(VERSION)
PLATFORMS = linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

# Default: everything CI runs except the auto-bump release step.
all: fmt-check vet build windows test e2e

# Compose the common pre-push checklist. Mirrors the CI matrix.
check: fmt-check vet windows test e2e

# gofmt the tree in place.
fmt:
	gofmt -w .

# Fail if anything in the tree is not gofmt-clean.
fmt-check:
	@out=$$(gofmt -l .); \
	if [ -n "$$out" ]; then echo "gofmt found unformatted files:"; echo "$$out"; exit 1; fi

# Static analysis across every package.
vet:
	go vet ./...

# Build the whole module for the host platform.
build:
	go build ./...

# Cross-compile + vet for Windows. A build-only smoke so a host-only library
# doesn't quietly stop building on the other major target.
windows:
	GOOS=windows go vet ./...
	GOOS=windows go build ./...

# Library unit + fuzz tests (v1alpha1) plus the godoc examples (v1).
test:
	go test ./...

# End-to-end: the harness builds and drives every example binary. -count=1 disables
# go test caching, since the harness builds the example binaries at runtime and the
# cache key wouldn't otherwise pick up example source changes.
e2e:
	go test -count=1 -v ./e2e

# Build the launcher for the host platform, stamped and stripped.
binary:
	go build -trimpath -ldflags "$(GO_LDFLAGS)" -o libtunnel ./cmd/libtunnel

# Cross-compile the launcher for every supported OS/arch into dist/, then
# write a SHA256SUMS manifest. Reproducible (-trimpath), stripped, static
# (CGO off) — the artifacts the release workflow attaches and signs.
dist:
	rm -rf dist
	mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		out=dist/libtunnel_$${os}_$${arch}; \
		[ "$$os" = windows ] && out=$$out.exe; \
		echo "building $$out"; \
		GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(GO_LDFLAGS)" -o $$out ./cmd/libtunnel || exit 1; \
	done
	cd dist && { command -v sha256sum >/dev/null 2>&1 && sha256sum * || shasum -a 256 *; } > SHA256SUMS
	@echo "dist/ contents:" && ls -1 dist

# Run an example by name, forwarding any trailing words as args:
#   make run basic
#   make run named
run:
	cd examples/$(word 2,$(MAKECMDGOALS)) && go run . $(wordlist 3,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Swallow the example name and forwarded args (extra goals) so make doesn't error.
%:
	@:
