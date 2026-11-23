GO_PROFILE_TOOLCHAIN := go$(shell sed -n 's/^go //p' go.mod)

.PHONY: build install check quality quality-windows lint lint-windows fmt native clean
PREFIX ?= $(HOME)/.local
build:
	mkdir -p bin
	python3 scripts/build-lifecycle.py --tool intent --output bin/intent --manifest bin/intent.build.json
install: build
	python3 scripts/install-lifecycle.py --tool intent --source-bin "$(CURDIR)/bin" --prefix "$(PREFIX)"
check: quality
	python3 scripts/check-assets.py
quality:
	GOTOOLCHAIN="$(GO_PROFILE_TOOLCHAIN)" python3 scripts/check-source-code.py go
lint:
	GOTOOLCHAIN="$(GO_PROFILE_TOOLCHAIN)" bash scripts/check-go.sh lint
fmt:
	GOTOOLCHAIN="$(GO_PROFILE_TOOLCHAIN)" bash scripts/check-go.sh fmt
native:
	python3 scripts/build-native.py
clean:
	rm -rf bin dist native/build

lint-windows:
	GOOS=windows CGO_ENABLED=0 GOTOOLCHAIN="$(GO_PROFILE_TOOLCHAIN)" bash scripts/check-go.sh lint

quality-windows: lint-windows
	GOOS=windows CGO_ENABLED=0 GOTOOLCHAIN="$(GO_PROFILE_TOOLCHAIN)" bash scripts/check-go.sh vuln
