# MCP SSH Bridge - Development Makefile

.PHONY: all build release check test lint fmt fmt-check audit deny clean install setup help typos machete outdated quality mutants mutants-db mutants-full security-audit geiger sbom security-tests semver-checks hack release-all release-target docker-build docker-scan deps-check deps-update ci-full release-pipeline

# Default target
all: check lint test

# Build debug version
build:
	cargo build

# Build release version
release:
	cargo build --release

# Check compilation without building
check:
	cargo check --all-targets

# Run tests
test:
	cargo nextest run 2>/dev/null || cargo test

# Run clippy linter
lint:
	cargo clippy --all-targets --all-features -- -D warnings

# Format code
fmt:
	cargo fmt --all

# Check formatting
fmt-check:
	cargo fmt --all -- --check

# Security audit (requires cargo-audit: cargo install cargo-audit)
audit:
	@command -v cargo-audit >/dev/null 2>&1 && cargo-audit audit || echo "cargo-audit not installed, skipping"

# License and dependency check
deny:
	cargo deny check

# Clean build artifacts
clean:
	cargo clean

# Install to ~/.cargo/bin
install: release
	cp target/release/mcp-ssh-bridge ~/.cargo/bin/

# Development mode with auto-reload
dev:
	cargo watch -x 'check --all-targets'

# Check for typos in code
typos:
	@command -v typos >/dev/null 2>&1 && typos || echo "typos not installed, skipping"

# Check for unused dependencies
machete:
	@command -v cargo-machete >/dev/null 2>&1 && cargo machete || echo "cargo-machete not installed, skipping"

# Check for outdated dependencies
outdated:
	@command -v cargo-outdated >/dev/null 2>&1 && cargo outdated || echo "cargo-outdated not installed, skipping"

# Full quality check (all linters)
quality: fmt-check lint typos machete

# Full CI check (quick)
ci: fmt-check lint test audit typos

# Full CI check (comprehensive - replaces GitHub Actions)
ci-full: fmt-check lint test audit typos hack geiger
	@echo "Full CI complete."

# Setup development environment
setup:
	@echo "Installing Rust dev tools..."
	rustup component add rustfmt clippy
	@echo "Installing cargo tools..."
	cargo install cargo-nextest cargo-deny cargo-audit cargo-watch cargo-machete cargo-outdated typos-cli cargo-semver-checks cargo-hack cargo-insta cargo-geiger cargo-cyclonedx cross --locked
	@echo "Installing pre-commit (requires Python)..."
	@command -v pip >/dev/null 2>&1 && pip install --user pre-commit && pre-commit install || echo "pip not found, skipping pre-commit"
	@echo "Installing markdownlint (requires Node.js)..."
	@command -v npm >/dev/null 2>&1 && npm install -g markdownlint-cli || echo "npm not found, skipping markdownlint"
	@echo ""
	@echo "Setup complete! Run 'make check' to verify."

# Mutation testing (security module only - fast)
mutants:
	@command -v cargo-mutants >/dev/null 2>&1 && cargo mutants --re '^src/security/' || echo "cargo-mutants not installed, run: cargo install --locked cargo-mutants"

# Mutation testing (database + domain modules)
mutants-db:
	@command -v cargo-mutants >/dev/null 2>&1 && cargo mutants --re '^src/domain/' || echo "cargo-mutants not installed, run: cargo install --locked cargo-mutants"

# Mutation testing (full project - slow)
mutants-full:
	@command -v cargo-mutants >/dev/null 2>&1 && cargo mutants || echo "cargo-mutants not installed, run: cargo install --locked cargo-mutants"

# Run adversarial security test suite
security-tests:
	cargo test --test security_audit -- --nocapture

# Full security audit (dependency audit + security tests + unsafe scan)
security-audit: audit deny security-tests geiger

# Scan for unsafe code in dependencies (requires cargo-geiger)
geiger:
	@command -v cargo-geiger >/dev/null 2>&1 && cargo geiger --all-features --output-format ascii || echo "cargo-geiger not installed, run: cargo install cargo-geiger --locked"

# Check for semver-breaking API changes (requires cargo-semver-checks)
semver-checks:
	@command -v cargo-semver-checks >/dev/null 2>&1 && cargo semver-checks || echo "cargo-semver-checks not installed, run: cargo install cargo-semver-checks --locked"

# Check all feature combinations compile (requires cargo-hack)
hack:
	@command -v cargo-hack >/dev/null 2>&1 && cargo hack check --feature-powerset --no-dev-deps || echo "cargo-hack not installed, run: cargo install cargo-hack --locked"

# Generate Software Bill of Materials (requires cargo-cyclonedx)
sbom:
	@command -v cargo-cyclonedx >/dev/null 2>&1 && cargo cyclonedx --format json --output-cdx || echo "cargo-cyclonedx not installed, run: cargo install cargo-cyclonedx --locked"

# Cross-compile for a specific target (requires cross: cargo install cross)
release-target:
	@test -n "$(TARGET)" || (echo "Usage: make release-target TARGET=x86_64-unknown-linux-gnu" && exit 1)
	@command -v cross >/dev/null 2>&1 && cross build --release --target $(TARGET) || cargo build --release --target $(TARGET)

# Cross-compile all release targets
release-all:
	@echo "Building release binaries..."
	@mkdir -p releases
	cargo build --release --target x86_64-unknown-linux-gnu
	@command -v cross >/dev/null 2>&1 && cross build --release --target aarch64-unknown-linux-gnu || echo "cross not installed, skipping arm64"
	@command -v cross >/dev/null 2>&1 && cross build --release --target x86_64-apple-darwin || echo "cross not installed, skipping macos-x86_64"
	@command -v cross >/dev/null 2>&1 && cross build --release --target aarch64-apple-darwin || echo "cross not installed, skipping macos-arm64"
	@command -v cross >/dev/null 2>&1 && cross build --release --target x86_64-pc-windows-gnu || echo "cross not installed, skipping windows"
	@echo "Packaging..."
	@test -f target/x86_64-unknown-linux-gnu/release/mcp-ssh-bridge && cd target/x86_64-unknown-linux-gnu/release && tar czf ../../../releases/mcp-ssh-bridge-linux-x86_64.tar.gz mcp-ssh-bridge && cd ../../../releases && sha256sum mcp-ssh-bridge-linux-x86_64.tar.gz > mcp-ssh-bridge-linux-x86_64.tar.gz.sha256 || true
	@test -f target/aarch64-unknown-linux-gnu/release/mcp-ssh-bridge && cd target/aarch64-unknown-linux-gnu/release && tar czf ../../../releases/mcp-ssh-bridge-linux-arm64.tar.gz mcp-ssh-bridge && cd ../../../releases && sha256sum mcp-ssh-bridge-linux-arm64.tar.gz > mcp-ssh-bridge-linux-arm64.tar.gz.sha256 || true
	@test -f target/x86_64-apple-darwin/release/mcp-ssh-bridge && cd target/x86_64-apple-darwin/release && tar czf ../../../releases/mcp-ssh-bridge-macos-x86_64.tar.gz mcp-ssh-bridge && cd ../../../releases && sha256sum mcp-ssh-bridge-macos-x86_64.tar.gz > mcp-ssh-bridge-macos-x86_64.tar.gz.sha256 || true
	@test -f target/aarch64-apple-darwin/release/mcp-ssh-bridge && cd target/aarch64-apple-darwin/release && tar czf ../../../releases/mcp-ssh-bridge-macos-arm64.tar.gz mcp-ssh-bridge && cd ../../../releases && sha256sum mcp-ssh-bridge-macos-arm64.tar.gz > mcp-ssh-bridge-macos-arm64.tar.gz.sha256 || true
	@test -f target/x86_64-pc-windows-gnu/release/mcp-ssh-bridge.exe && cd target/x86_64-pc-windows-gnu/release && zip -j ../../../releases/mcp-ssh-bridge-windows-x86_64.zip mcp-ssh-bridge.exe && cd ../../../releases && sha256sum mcp-ssh-bridge-windows-x86_64.zip > mcp-ssh-bridge-windows-x86_64.zip.sha256 || true
	@echo "Release artifacts in releases/"

# Build Docker image locally
docker-build:
	docker build -t mcp-ssh-bridge:local .

# Build and scan Docker image with Trivy
docker-scan: docker-build
	@command -v trivy >/dev/null 2>&1 && trivy image --severity CRITICAL,HIGH mcp-ssh-bridge:local || echo "trivy not installed, skipping scan"

# Check for outdated and unused dependencies (replaces Dependabot)
deps-check: outdated machete
	@echo "Dependency check complete. Run 'cargo update' to apply compatible updates."

# Update all compatible dependencies (minor/patch)
deps-update:
	cargo update
	@echo "Updated Cargo.lock with compatible versions."
	@echo "Run 'make outdated' to see remaining major updates."

# Full release pipeline (CI + cross-compile + Docker)
release-pipeline: ci-full release-all docker-scan
	@echo "Release pipeline complete."

# Show help
help:
	@echo "MCP SSH Bridge - Available targets:"
	@echo ""
	@echo "Build:"
	@echo "  build            - Build debug version"
	@echo "  release          - Build release version (native)"
	@echo "  release-all      - Cross-compile all 5 platforms"
	@echo "  release-target   - Build specific target (TARGET=...)"
	@echo "  check            - Check compilation"
	@echo "  clean            - Clean build artifacts"
	@echo "  install          - Install to ~/.cargo/bin"
	@echo ""
	@echo "Quality:"
	@echo "  test             - Run tests"
	@echo "  lint             - Run clippy"
	@echo "  fmt              - Format code"
	@echo "  fmt-check        - Check formatting"
	@echo "  typos            - Check for typos"
	@echo "  hack             - Check all feature combinations"
	@echo "  quality          - Full quality check (lint+typos+machete)"
	@echo ""
	@echo "Security:"
	@echo "  audit            - Security audit (cargo-audit)"
	@echo "  deny             - License/dependency check"
	@echo "  geiger           - Scan for unsafe code in dependencies"
	@echo "  security-tests   - Run adversarial security tests"
	@echo "  security-audit   - Full security audit (audit+deny+tests+geiger)"
	@echo ""
	@echo "Dependencies:"
	@echo "  deps-check       - Check outdated + unused (replaces Dependabot)"
	@echo "  deps-update      - Update compatible dependencies"
	@echo "  machete          - Check for unused dependencies"
	@echo "  outdated         - Check for outdated dependencies"
	@echo "  sbom             - Generate SBOM (CycloneDX)"
	@echo ""
	@echo "Testing:"
	@echo "  mutants          - Mutation testing (security module)"
	@echo "  mutants-db       - Mutation testing (domain/database)"
	@echo "  mutants-full     - Mutation testing (full project)"
	@echo "  semver-checks    - Check for semver-breaking changes"
	@echo ""
	@echo "Docker:"
	@echo "  docker-build     - Build Docker image locally"
	@echo "  docker-scan      - Build + Trivy security scan"
	@echo ""
	@echo "Pipelines:"
	@echo "  ci               - Quick CI (fmt+lint+test+audit+typos)"
	@echo "  ci-full          - Full CI (ci+hack+geiger)"
	@echo "  release-pipeline - Full release (ci-full+release-all+docker-scan)"
	@echo ""
	@echo "Development:"
	@echo "  dev              - Watch mode with auto-check"
	@echo "  setup            - Install all dev dependencies"
	@echo ""
