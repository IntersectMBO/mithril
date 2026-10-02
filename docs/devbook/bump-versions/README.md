# Bump the project versions before merging a pull request

## Introduction

This devbook provides a script that allows to automatically bump the versions of the crates, js packages,
Open API specification and plain version files in the project.

Only the resources with changes on the branch compared to `origin/main` are bumped:

| Resource                                               | Bumped when a change is detected in                             |
| ------------------------------------------------------ | --------------------------------------------------------------- |
| Crates                                                 | `src/`, `tests/`, `benches/` or `Cargo.toml` of the crate       |
| JS packages                                            | The directory of the package                                    |
| `openapi.yaml`                                         | The file itself                                                 |
| `mithril-infra/assets/infra.version`                   | `*.tf` files of `mithril-infra/`                                |
| `mithril-test-lab/cardano-devnet/VERSION`              | `*.sh` files of `mithril-test-lab/cardano-devnet/`              |
| `mithril-test-lab/benchmark/aggregator-prover/VERSION` | `*.sh` files of `mithril-test-lab/benchmark/aggregator-prover/` |
| `mithril-test-lab/ipfs-devnet/VERSION`                 | `*.sh` files of `mithril-test-lab/ipfs-devnet/`                 |

## Prerequisites

It requires to have `cargo-get` installed, which can be done with the following command:

```
cargo install cargo-get
```

## Usage

> [!NOTE]
> All commands are executed from the root of the repository.

### Dry-run

Just run the script without argument, by default no changes are made to the project.

```shell
./docs/devbook/bump-versions/bump_versions.sh
```

### Run

> [!IMPORTANT]
> The version bump is not based on the version on `origin/main`, but on the actual version in the branch.
>
> This means that running the script more than once will bump the versions again.

Run the script with the `--run` argument to bump the versions.

The script will output a preformatted commit message that can be used to create a commit when it completes.

```shell
./docs/devbook/bump-versions/bump_versions.sh --run
```

If you want the script to do the commit for you, add the `--commit` argument.

```shell
./docs/devbook/bump-versions/bump_versions.sh --run --commit
```

> [!NOTE]
> The `--commit` argument have no effect if `--run` is not specified.
