# Mithril-circuit-key-registry

This crate provides the genesis-signed registry of the circuit verification keys trusted for the
SNARK certificates of a Mithril network.

It holds:

- the registry format, whitelisting circuit verification key digests over epoch ranges and
  revoking them, and its genesis signature,
- the certifiers checking the circuit verification key digests of a certificate against the
  registry, with a cache refreshing the registry periodically,
- the retriever of the signed registry from a local file.

The nodes enforce the registry through the `CircuitVerificationKeyCertifier` trait of
`mithril-common`.
