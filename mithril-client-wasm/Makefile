%:
    @:

.PHONY: all build test check clean doc

args = `arg="$(filter-out $@,$(MAKECMDGOALS))" && echo $${arg:-${1}}`

CARGO = cargo

all: test build

build:
	npm run build

test:
	pkill -f "[m]ithril-aggregator-fake" || true
	${CARGO} run -p mithril-aggregator-fake -- -p 8000 &
	if ! wasm-pack test --headless --firefox --chrome --release; then \
		pkill -f "[m]ithril-aggregator-fake" || true; \
        exit 1; \
    fi
	if ! wasm-pack test --node --release --features test-node; then \
		pkill -f "[m]ithril-aggregator-fake" || true; \
		exit 1; \
	fi
	pkill -f "[m]ithril-aggregator-fake" || true

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
