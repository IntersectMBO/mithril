%:
    @:

.PHONY: all build test check clean doc

args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

CARGO = cargo

all: test build

build:
	npm run build

test:
	./run-tests.sh

check:
	${CARGO} check --release --all-features --all-targets
	${CARGO} clippy --release --all-features --all-targets
	${CARGO} fmt --check

clean:
	${CARGO} clean

doc:
	${CARGO} doc --no-deps --open --target wasm32-unknown-unknown

ci-test-install:
	npm --prefix ci-test install

ci-test-serve:
	npm --prefix ci-test run start

upgrade-ci-test-deps: build
	make -C ci-test upgrade

lint:
	make -C ci-test lint

format:
	make -C ci-test format
