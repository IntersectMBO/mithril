# Manage the circuit verification key registry

## When to use this guide

The circuit verification key registry is a genesis-signed whitelist of the circuit verification keys trusted for SNARK certificates (`Snark` and `IvcSnark` aggregate signature types). Clients resolve the registry of their network at runtime through the published `networks.json`: they select the network entry whose aggregators include their aggregator endpoint and download the signed registry file it references. Aggregators read the registry from a local file path. Both reject any SNARK certificate whose circuit verification keys are not certified by it. `networks.json` is pure routing, never trust: a wrong entry can only yield a registry that fails the genesis signature verification. Use this guide when:

- a new circuit verification key enters service (new deployment, or a circuit change following [update-circuit-keys](../update-circuit-keys/README.md)),
- a circuit verification key is rotated out normally,
- a circuit or key turns out to be insecure and its certificates must be revoked.

## Registry format

The registry is a JSON document published per network as `mithril-infra/configuration/<network>/circuit-verification-key-registry.json`, next to the network's other trust material, and referenced from the network's `networks.json` entry (devnet and the end to end tests generate theirs on the fly with the test-only `circuit-key-registry bootstrap` command):

```json
"circuit-verification-key-registry": {
  "url": "https://raw.githubusercontent.com/IntersectMBO/mithril/main/mithril-infra/configuration/release-mainnet/circuit-verification-key-registry.json"
}
```

Its content is:

```json
{
  "registry": {
    "version": 2,
    "entries": [
      {
        "digest": "3e5a…9c1f",
        "name": "certificate-circuit v1",
        "status": "allowed",
        "start_epoch": 500,
        "end_epoch": null,
        "comment": null
      },
      {
        "digest": "7bd2…04aa",
        "name": "ivc-circuit v1",
        "status": "revoked",
        "start_epoch": 520,
        "end_epoch": null,
        "comment": "revoked: soundness issue in the accumulator check"
      }
    ]
  },
  "signature": "…"
}
```

Semantics enforced by the nodes:

- A digest absent from the registry is rejected (whitelist).
- An `allowed` entry covers the inclusive epoch range `[start_epoch, end_epoch]` (`end_epoch: null` is open-ended).
- A `revoked` entry overrides any `allowed` entry wherever their ranges overlap (revocation wins), so certificates in the revoked range are rejected retroactively.
- `version` must increase at every publication; nodes reject a registry older than their compiled minimum version. That minimum (`MINIMUM_REGISTRY_VERSION`) is a single floor shared by every network: bump it only once every network's registry has been re-signed at or above the new floor, otherwise clients of the other networks fail closed.
- The `signature` is the Ed25519 half of the genesis key over the canonical JSON bytes of the `registry` object.
- The registry is scoped by the genesis key that signs it: a registry signed for another network fails the signature check. This relies on the invariant that networks never share a genesis key.

The digests are domain separated Poseidon hashes (SNARK-friendly, native to the scalar field of the circuits) of the transcript representation of the verification keys, the field element Halo2 derives from the pinned constraint system, the evaluation domain and the commitments, so they bind the circuit gates and not only the serialized key bytes. The two circuits behave differently:

- The IVC circuit does not depend on the protocol parameters: its verification key is the production constant embedded in `mithril-stm`, so its digest is the same for every network.
- The certificate circuit depends on the protocol parameters (`k` and `m`): its verification key, hence its digest, changes with them. The registry must allow the digest of the protocol parameters the network signs with, so a protocol parameters update changing `k` or `m` must be preceded by a registry publication allowing the digest of the new parameters.

The digests are exported with the aggregator (the certificate circuit key is derived from the trusted setup for the given protocol parameters, which is fast for small `k`; without `--protocol-parameters` the production certificate circuit key embedded in `mithril-stm` is used):

```bash
./mithril-aggregator circuit-key-registry export \
    --protocol-parameters '{"k":2422,"m":20973,"phi_f":0.2}' \
    --target-path digests.json
```

The digests can also be read from the ancillary verifier data of a certificate produced with the keys (certificate circuit first, then IVC circuit), and the production ones are printed by the ignored `print_circuit_verification_key_digests_for_production` test of `mithril-stm`.

## Publish a new registry version

1. Export the digests of the keys concerned (see above) on a machine with network access.
2. On the air-gapped machine holding the genesis secret key, add the entry to the current signed registry with `whitelist` or `revoke`: the command verifies the existing registry signature, appends the entry, increments the `version`, signs and writes the file in place (it creates the registry when the file does not exist yet):

```bash
./mithril-aggregator circuit-key-registry whitelist \
    --registry-path circuit-verification-key-registry.json \
    --genesis-secret-key-path genesis.sk \
    --digest 3e5a…9c1f \
    --name "certificate-circuit v1" \
    --start-epoch 500

./mithril-aggregator circuit-key-registry revoke \
    --registry-path circuit-verification-key-registry.json \
    --genesis-secret-key-path genesis.sk \
    --digest 7bd2…04aa \
    --name "ivc-circuit v1" \
    --start-epoch 520 \
    --comment "revoked: soundness issue in the accumulator check"
```

Both commands accept `--end-epoch` to close the range and `--comment` to record the reason (mandatory for a revocation). A hand-authored unsigned registry can still be signed as a whole with `circuit-key-registry sign --to-sign-registry-path registry.json --target-signed-registry-path circuit-verification-key-registry.json --genesis-secret-key-path genesis.sk`.

3. Open a PR committing the signed file at `mithril-infra/configuration/<network>/circuit-verification-key-registry.json`, referencing it from the network's `networks.json` entry (first publication only), and have it reviewed by the tech lead and the cryptographers.
4. Once merged on `main`, the file is live: clients resolve and download it through `networks.json`, and aggregators read it from the path set in their `circuit_verification_key_registry_path` configuration, which defaults to `circuit-verification-key-registry.json` in the aggregator data stores directory (update the deployed file accordingly).

Running nodes cache the verified registry for one hour before retrieving and verifying it again (downloads are retried), so a new version (including a revocation) is picked up without restarting them; a refresh never accepts a registry version lower than the one already verified.

For tests and local deployments, the unstable `--circuit-verification-key-registry-path` parameter of the client CLI (or the `CIRCUIT_VERIFICATION_KEY_REGISTRY_PATH` environment variable) makes it read the signed registry from a local file instead of resolving it through `networks.json`; it only changes the source, the genesis signature verification still applies. Library users get the same through `with_circuit_verification_key_registry_retriever` on the client builder.

## Lifecycle procedures

### New key entering service

`whitelist` the digest with `--start-epoch` set to the first epoch the key certifies and no `--end-epoch`.

### Normal rotation

Close the outgoing key's `allowed` entry by setting its `end_epoch` to the last epoch it legitimately certified (edit the registry and sign it as a whole), and `whitelist` the incoming key. Certificates from the closed range keep verifying forever.

### Revocation after a vulnerability

1. Determine the epoch range in which the flaw is exploitable. For a soundness flaw (forged certificates possible), always revoke the key's whole lifetime: a forger chooses the epoch its certificate claims, so a partial range only helps for flaws that are externally time-bound.
2. `revoke` the digest over that range with an explanatory `--comment`; the original `allowed` entry stays untouched as an audit trail.
3. Publish the new registry version (see above).
4. Bump the `MINIMUM_REGISTRY_VERSION` constant in `mithril-common` (`crypto_helper/circuit_key_registry/certifier.rs`) to the new version and release the clients, so an attacker replaying the previous signed registry cannot resurrect the revoked key.
5. Proceed to a re-genesis with the fixed circuit keys ([update-circuit-keys](../update-circuit-keys/README.md) and [genesis-manually](../genesis-manually/README.md)).
