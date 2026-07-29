.PHONY: all build release build-ebpf build-ebpf-release build-cli build-cli-release clean test check fmt fmt-check dev help selinux-build selinux-install smoke

CARGO := cargo
TARGET_DIR := target
UNAME := $(shell uname)

all: build

ifeq ($(UNAME),Linux)
build: build-ebpf build-cli

release: build-ebpf-release build-cli-release
	@echo "Release build complete: target/release/tls-probe"
else
build:
	@echo "eBPF build requires Linux. Building CLI only..."
	@$(MAKE) build-cli

release:
	@echo "eBPF build requires Linux. Building CLI release only..."
	@$(MAKE) build-cli-release
endif

help:
	@echo "tls-probe build targets:"
	@echo ""
	@echo "Cross-platform (macOS/Linux):"
	@echo "  dev            - Development workflow: fmt, clippy, build-cli, test"
	@echo "  build-cli      - Build CLI tool only"
	@echo "  check          - Run cargo check and clippy"
	@echo "  test           - Run unit tests"
	@echo "  fmt            - Format code"
	@echo "  clean          - Clean build artifacts"
	@echo ""
	@echo "Linux only:"
	@echo "  build          - Build everything (eBPF + CLI) in debug mode"
	@echo "  release        - Build everything in release mode"
	@echo "  build-ebpf     - Build eBPF probes"
	@echo "  smoke          - Run the runtime smoke test (needs root; builds release first)"
	@echo ""
	@echo "SELinux (RHEL/Fedora):"
	@echo "  selinux-build  - Build SELinux policy module"
	@echo "  selinux-install - Install SELinux policy module"

dev: fmt check build-cli test
	@echo "Development build complete"

build-ebpf:
	$(CARGO) xtask build-ebpf

build-ebpf-release:
	$(CARGO) xtask build-ebpf --profile release

build-cli:
	$(CARGO) build -p tls-probe

build-cli-release:
	$(CARGO) build -p tls-probe --release

clean:
	$(CARGO) clean

test:
	$(CARGO) test -p tls-probe-common -p tls-probe-parser -p tls-probe

check:
	$(CARGO) check -p tls-probe-common -p tls-probe-parser -p tls-probe
	$(CARGO) clippy -p tls-probe-common -p tls-probe-parser -p tls-probe -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

# Same script CI runs. Root is required to load and attach the probes.
smoke: release
	sudo python3 scripts/smoke_test.py \
		--probe target/release/tls-probe \
		--ebpf target/bpfel-unknown-none/release/tls-probe-ebpf \
		--schema specs/capture-event.schema.json \
		--workdir smoke-run

selinux-build:
	cd selinux && make

selinux-install:
	cd selinux && make install
