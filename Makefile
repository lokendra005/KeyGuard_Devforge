export PATH := $(CURDIR)/.cache/toolchain/bin:$(PATH)
GO_ENV = GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOCACHE=$(CURDIR)/.cache/build
.PHONY: build test unit crypto vet fuzz bench release run track4-test track4-review
track4-test:
	node --test track4/test/*.test.cjs
track4-review:
	./scripts/track4-review.sh --docker
build:
	mkdir -p dist
	$(GO_ENV) CGO_ENABLED=0 go build -mod=vendor -trimpath -ldflags='-s -w' -o dist/kig ./cmd/kig
unit:
	$(GO_ENV) go test -mod=vendor -race ./...
crypto:
	$(GO_ENV) go test -mod=vendor -race -count=1 ./internal/guard -run 'TestSHA384TreeAndSuiteBinding|TestIndependentMLDSAVectors|TestMalformedExpandedPrivateKey|TestCorruptRounding|TestMLDSAContext|TestOpenSSLInteroperability' -v
	$(GO_ENV) go test -mod=vendor -race -count=1 ./spec -v
test:
	./scripts/test.sh
vet:
	$(GO_ENV) go vet -mod=vendor ./...
fuzz:
	$(GO_ENV) go test -mod=vendor ./internal/guard -run '^$$' -fuzz FuzzStrictJSON -fuzztime 10s -parallel 2
bench:
	$(GO_ENV) go test -mod=vendor ./internal/guard -run '^$$' -bench BenchmarkMLDSA65 -benchmem
release:
	./scripts/release.sh
smoke: build
	./scripts/smoke.sh
