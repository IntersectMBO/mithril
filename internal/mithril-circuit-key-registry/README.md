# Mithril-circuit-key-registry

This crate provides the genesis-signed registry of the circuit verification keys trusted for the
SNARK certificates of a Mithril network.

It holds:

- the registry format, with one entry per circuit verification key digest, either allowed over an
  epoch range or revoked, and its genesis signature,
- the certifiers checking the circuit verification key digests of a certificate against the
  registry, with a cache refreshing the registry periodically and keeping the last verified
  registry for at most a day when the refreshes fail,
- the retrievers of the signed registry from a local file or over HTTP.

The nodes enforce the registry through the `CircuitVerificationKeyCertifier` trait of
`mithril-common`.
