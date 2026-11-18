.PHONY: all build test check doc

CARGO = cargo

all: test build

build:
	${CARGO} build --release

test:
	${CARGO} test

check:
	${CARGO} check --release --all-features --all-targets
	${CARGO} clippy --release --all-features --all-targets
	${CARGO} fmt --check

doc:
	${CARGO} doc --no-deps --open
