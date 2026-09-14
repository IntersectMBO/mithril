.PHONY: all build test check doc

CARGO = cargo

all: test build

build:
	${CARGO} build --release --features future_snark

test:
	${CARGO} test --features future_snark

check:
	${CARGO} check --release --all-features --all-targets
	${CARGO} clippy --release --all-features --all-targets
	${CARGO} fmt --check

doc:
	${CARGO} doc --no-deps --open --features future_snark
