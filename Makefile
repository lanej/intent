.PHONY: build install check lint fmt native clean
PREFIX ?= $(HOME)/.local
build:
	mkdir -p bin
	go build -o bin/intent ./cmd/intent
install: build
	install -d "$(PREFIX)/bin"
	install -m 755 bin/intent "$(PREFIX)/bin/intent"
check:
	@test -z "$$(gofmt -s -l .)" || (gofmt -s -l .; exit 1)
	go vet ./...
	go test -race ./...
	python3 scripts/check-assets.py
lint:
	golangci-lint run
fmt:
	golangci-lint fmt
native:
	python3 scripts/build-native.py
clean:
	rm -rf bin dist native/build
