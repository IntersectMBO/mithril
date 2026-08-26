COMPONENTS = demo/protocol-demo \
			 internal/cardano-node/mithril-cardano-node-chain \
			 internal/cardano-node/mithril-cardano-node-internal-database \
			 internal/mithril-aggregator-client \
			 internal/mithril-aggregator-discovery \
			 internal/mithril-build-script \
			 internal/mithril-cli-helper \
			 internal/mithril-dmq \
			 internal/mithril-doc \
			 internal/mithril-doc-derive \
			 internal/mithril-era \
			 internal/mithril-file-archiver \
			 internal/mithril-metric \
			 internal/mithril-persistence \
			 internal/mithril-protocol-config \
			 internal/mithril-resource-pool \
			 internal/mithril-ticker \
			 internal/signed-entity/mithril-signed-entity-lock \
			 internal/signed-entity/mithril-signed-entity-preloader \
			 internal/tests/mithril-api-spec \
			 internal/tests/mithril-test-http-server \
			 mithril-aggregator \
			 mithril-client \
			 mithril-client-cli \
			 mithril-client-wasm \
			 mithril-common \
			 mithril-relay \
			 mithril-signer \
			 mithril-stm \
			 mithril-test-lab/mithril-aggregator-fake \
			 mithril-test-lab/mithril-end-to-end
GOALS := $(or $(MAKECMDGOALS),all)
NON_COMPONENT_GOALS := check-format format

.PHONY: $(GOALS) $(COMPONENTS) $(NON_COMPONENT_GOALS)

$(filter-out $(NON_COMPONENT_GOALS),$(GOALS)): $(COMPONENTS)

$(COMPONENTS):
	$(MAKE) -C $@ $(MAKECMDGOALS)

check-format:
	@echo 'Note: Rust is not checked by this recipe, use `make check`'
	@which prettier >/dev/null || echo 'It seems 'prettier' is not installed or not in the path. see https://prettier.io/docs/en/install';
	prettier --check .

format:
	@which prettier >/dev/null || echo 'It seems 'prettier' is not installed or not in the path. see https://prettier.io/docs/en/install';
	prettier --write .
