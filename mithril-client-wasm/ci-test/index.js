import initMithrilClient, { MithrilClient } from "@mithril-dev/mithril-client-wasm";

async function run_test(test_name, test_number, fun) {
  try {
    const result = await fun();
    display_test_result_in_dom(test_name, test_number, "OK");
    return result;
  } catch (error) {
    handle_error(test_name, test_number, error);
  }
}

function display_test_result_in_dom(test_name, test_number, result, error) {
  let div = document.createElement("div");
  div.id = test_name;
  div.title = result;
  div.innerHTML = `Result test n°${test_number}: ${result}; function_name: ${test_name}${
    error ? `; reason: ${error}` : ""
  }`;
  document.body.appendChild(div);
}

function handle_error(test_name, test_number, error) {
  display_test_result_in_dom(test_name, test_number, "FAILED", error);
  console.error(`Error at step ${test_number} (${test_name}):`, error);
  add_finished_div();
  throw new Error(`Stopping script due to error at step ${test_number}: ${error}`);
}

function add_finished_div() {
  let div = document.createElement("div");
  div.id = "tests_finished";
  document.body.appendChild(div);
}

const mithril_events = [];
const mithril_events_channel = new BroadcastChannel("mithril-client");
mithril_events_channel.onmessage = (message) => mithril_events.push(message.data);

function count_events(event_type) {
  return mithril_events.filter((event) => event.type === event_type).length;
}

async function wait_for_events(event_type, expected_count) {
  const deadline = Date.now() + 10_000;
  while (count_events(event_type) < expected_count) {
    if (Date.now() > deadline) {
      throw new Error(`Timeout waiting for ${expected_count} '${event_type}' events`);
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

async function verify_certificate_chain_and_count_cache_hits(certificate_hash) {
  const chain_validations_before = count_events("CertificateChainValidated");
  const cache_hits_before = count_events("CertificateFetchedFromCache");
  const certificate = await client.verify_certificate_chain(certificate_hash);
  await wait_for_events("CertificateChainValidated", chain_validations_before + 1);
  const cache_hits = count_events("CertificateFetchedFromCache") - cache_hits_before;
  return { certificate, cache_hits };
}

await initMithrilClient();
const aggregator_endpoint = process.env.AGGREGATOR_ENDPOINT;
const genesis_verification_key = process.env.GENESIS_VERIFICATION_KEY;
let client;
let test_number = 1;

const aggregator_capabilities = await fetch(aggregator_endpoint)
  .then((res) => (res.status === 200 ? res.json() : []))
  .then((res) => res.capabilities?.signed_entity_types ?? []);
console.log("aggregator_endpoint: ", aggregator_endpoint);
console.log("aggregator_capabilities: ", aggregator_capabilities);

await run_test("constructor", test_number, async () => {
  client = new MithrilClient(aggregator_endpoint, genesis_verification_key, {
    origin_tag: "CI",
    // The following option activates the unstable features of the client.
    // Unstable features will trigger an error if this option is not set.
    unstable: true,
    enable_certificate_chain_verification_cache: true,
  });
});

test_number++;
await run_test("is_certificate_verifier_cache_enabled", test_number, async () => {
  if (!(await client.is_certificate_verifier_cache_enabled())) {
    throw new Error("The certificate verifier cache should be enabled");
  }
});

if (aggregator_capabilities.includes("CardanoBlocksTransactions")) {
  const transactions_hashes_to_certify =
    process.env.TRANSACTIONS_HASHES_TO_CERTIFY?.split(",") ?? [];
  const blocks_hashes_to_certify = process.env.BLOCKS_HASHES_TO_CERTIFY?.split(",") ?? [];

  let ctx_sets;
  test_number++;
  await run_test("list_cardano_transactions_v2_snapshots", test_number, async () => {
    ctx_sets = await client.list_cardano_transactions_v2_snapshots();
    console.log("cardano_blocks_transactions_sets", ctx_sets);
  });

  test_number++;
  await run_test("get_cardano_transactions_v2_snapshot", test_number, async () => {
    const ctx_set = await client.get_cardano_transactions_v2_snapshot(ctx_sets[0].hash);
    console.log("cardano_blocks_transactions_set", ctx_set);
  });

  if (transactions_hashes_to_certify.length > 0) {
    console.log("Testing transactions V2 certification with txs:", transactions_hashes_to_certify);

    let ctx_proof;
    test_number++;
    await run_test("get_cardano_transaction_v2_proof", test_number, async () => {
      ctx_proof = await client.get_cardano_transaction_v2_proof(transactions_hashes_to_certify);
      console.log(
        "got proof for transactions V2: ",
        ctx_proof.transactions_hashes,
        "\nnon_certified_transactions V2: ",
        ctx_proof.non_certified_transactions,
      );
    });

    let proof_certificate;
    test_number++;
    await run_test("proof_v2_verify_certificate_chain", test_number, async () => {
      proof_certificate = await client.verify_certificate_chain(ctx_proof.certificate_hash);
      console.log("proof_certificate", proof_certificate);
    });

    let ctx_proof_message;
    test_number++;
    await run_test(
      "verify_cardano_transaction_v2_proof_then_compute_message",
      test_number,
      async () => {
        ctx_proof_message = await client.verify_cardano_transaction_v2_proof_then_compute_message(
          ctx_proof,
          proof_certificate,
        );
        console.log("verify_cardano_transaction_v2_proof_then_compute_message", ctx_proof_message);
      },
    );

    test_number++;
    await run_test("proof_v2_verify_message_match_certificate", test_number, async () => {
      const valid_stake_distribution_message = await client.verify_message_match_certificate(
        ctx_proof_message,
        proof_certificate,
      );
      console.log("valid_stake_distribution_message", valid_stake_distribution_message);
    });
  }

  let cardano_blocks_sets;
  test_number++;
  await run_test("list_cardano_blocks_snapshots", test_number, async () => {
    cardano_blocks_sets = await client.list_cardano_blocks_snapshots();
    console.log("cardano_blocks_sets", cardano_blocks_sets);
  });

  test_number++;
  await run_test("get_cardano_blocks_snapshot", test_number, async () => {
    const cardano_blocks_set = await client.get_cardano_blocks_snapshot(
      cardano_blocks_sets[0].hash,
    );
    console.log("cardano_blocks_set", cardano_blocks_set);
  });

  if (blocks_hashes_to_certify.length > 0) {
    console.log("Testing blocks certification with blocks hashes:", blocks_hashes_to_certify);

    let cardano_block_proof;
    test_number++;
    await run_test("get_cardano_block_proof", test_number, async () => {
      cardano_block_proof = await client.get_cardano_block_proof(blocks_hashes_to_certify);
      console.log(
        "got proof for blocks: ",
        cardano_block_proof.blocks_hashes,
        "\nnon_certified_blocks: ",
        cardano_block_proof.non_certified_blocks,
      );
    });

    let proof_certificate;
    test_number++;
    await run_test("proof_v2_verify_certificate_chain", test_number, async () => {
      proof_certificate = await client.verify_certificate_chain(
        cardano_block_proof.certificate_hash,
      );
      console.log("proof_certificate", proof_certificate);
    });

    let cardano_block_proof_message;
    test_number++;
    await run_test("verify_cardano_block_proof_then_compute_message", test_number, async () => {
      cardano_block_proof_message = await client.verify_cardano_block_proof_then_compute_message(
        cardano_block_proof,
        proof_certificate,
      );
      console.log("verify_cardano_block_proof_then_compute_message", cardano_block_proof_message);
    });

    test_number++;
    await run_test("proof_v2_verify_message_match_certificate", test_number, async () => {
      const valid_stake_distribution_message = await client.verify_message_match_certificate(
        cardano_block_proof_message,
        proof_certificate,
      );
      console.log("valid_stake_distribution_message", valid_stake_distribution_message);
    });
  }
}

let mithril_stake_distributions;
test_number++;
await run_test("list_mithril_stake_distributions", test_number, async () => {
  mithril_stake_distributions = await client.list_mithril_stake_distributions();
  console.log("mithril_stake_distributions", mithril_stake_distributions);
});

let mithril_stake_distribution;
test_number++;
await run_test("get_mithril_stake_distribution", test_number, async () => {
  mithril_stake_distribution = await client.get_mithril_stake_distribution(
    mithril_stake_distributions[0].hash,
  );
  console.log("mithril_stake_distribution", mithril_stake_distribution);
});

let certificate;
test_number++;
await run_test("get_mithril_certificate", test_number, async () => {
  certificate = await client.get_mithril_certificate(mithril_stake_distribution.certificate_hash);
  console.log("certificate", certificate);
});

let last_certificate_from_chain;
test_number++;
await run_test("verify_certificate_chain", test_number, async () => {
  last_certificate_from_chain = await client.verify_certificate_chain(certificate.hash);
  console.log("last_certificate_from_chain", last_certificate_from_chain);
});

test_number++;
await run_test("verify_certificate_chain_from_cache", test_number, async () => {
  const { cache_hits } = await verify_certificate_chain_and_count_cache_hits(certificate.hash);
  if (cache_hits === 0) {
    throw new Error("No certificate was fetched from the cache");
  }
  console.log("certificates fetched from the cache", cache_hits);
});

test_number++;
await run_test("reset_certificate_verifier_cache", test_number, async () => {
  await client.reset_certificate_verifier_cache();
  const { cache_hits } = await verify_certificate_chain_and_count_cache_hits(certificate.hash);
  if (cache_hits > 0) {
    throw new Error(`${cache_hits} certificates were fetched from the cache after its reset`);
  }
});

let mithril_stake_distribution_message;
test_number++;
await run_test("compute_mithril_stake_distribution_message", test_number, async () => {
  mithril_stake_distribution_message = await client.compute_mithril_stake_distribution_message(
    mithril_stake_distribution,
    last_certificate_from_chain,
  );
  console.log("mithril_stake_distribution_message", mithril_stake_distribution_message);
});

test_number++;
await run_test("verify_message_match_certificate", test_number, async () => {
  const valid_stake_distribution_message = await client.verify_message_match_certificate(
    mithril_stake_distribution_message,
    last_certificate_from_chain,
  );
  console.log("valid_stake_distribution_message", valid_stake_distribution_message);
});

if (aggregator_capabilities.includes("CardanoTransactions")) {
  const transactions_hashes_to_certify =
    process.env.TRANSACTIONS_HASHES_TO_CERTIFY?.split(",") ?? [];

  let ctx_sets;
  test_number++;
  await run_test("list_cardano_transactions_snapshots", test_number, async () => {
    ctx_sets = await client.list_cardano_transactions_snapshots();
    console.log("cardano_transactions_sets", ctx_sets);
  });

  test_number++;
  await run_test("get_cardano_transactions_snapshot", test_number, async () => {
    const ctx_set = await client.get_cardano_transactions_snapshot(ctx_sets[0].hash);
    console.log("cardano_transaction_set", ctx_set);
  });

  if (transactions_hashes_to_certify.length > 0) {
    console.log("Testing transactions certification with txs:", transactions_hashes_to_certify);

    let ctx_proof;
    test_number++;
    await run_test("get_cardano_transaction_proof", test_number, async () => {
      ctx_proof = await client.get_cardano_transaction_proofs(transactions_hashes_to_certify);
      console.log(
        "got proof for transactions: ",
        ctx_proof.transactions_hashes,
        "\nnon_certified_transactions: ",
        ctx_proof.non_certified_transactions,
      );
    });

    let proof_certificate;
    test_number++;
    await run_test("proof_verify_certificate_chain", test_number, async () => {
      proof_certificate = await client.verify_certificate_chain(ctx_proof.certificate_hash);
      console.log("proof_certificate", proof_certificate);
    });

    let ctx_proof_message;
    test_number++;
    await run_test(
      "verify_cardano_transaction_proof_then_compute_message",
      test_number,
      async () => {
        ctx_proof_message = await client.verify_cardano_transaction_proof_then_compute_message(
          ctx_proof,
          proof_certificate,
        );
        console.log("verify_cardano_transaction_proof_then_compute_message", ctx_proof_message);
      },
    );

    test_number++;
    await run_test("proof_verify_message_match_certificate", test_number, async () => {
      const valid_stake_distribution_message = await client.verify_message_match_certificate(
        ctx_proof_message,
        proof_certificate,
      );
      console.log("valid_stake_distribution_message", valid_stake_distribution_message);
    });
  }
}

if (aggregator_capabilities.includes("CardanoStakeDistribution")) {
  let cardano_stake_distributions;
  test_number++;
  await run_test("list_cardano_stake_distributions", test_number, async () => {
    cardano_stake_distributions = await client.list_cardano_stake_distributions();
    console.log("cardano_stake_distributions", cardano_stake_distributions);
  });

  let cardano_stake_distribution;
  test_number++;
  await run_test("get_cardano_stake_distribution", test_number, async () => {
    cardano_stake_distribution = await client.get_cardano_stake_distribution(
      cardano_stake_distributions[0].hash,
    );
    console.log("cardano_stake_distribution", cardano_stake_distribution);
  });

  test_number++;
  await run_test("get_cardano_stake_distribution_by_epoch", test_number, async () => {
    let epoch = BigInt(cardano_stake_distributions[0].epoch);

    let cardano_stake_distribution_by_epoch =
      await client.get_cardano_stake_distribution_by_epoch(epoch);
    console.log("cardano_stake_distribution by epoch", cardano_stake_distribution_by_epoch);
  });

  test_number++;
  await run_test("get_cardano_stake_distribution_for_latest_epoch", test_number, async () => {
    let cardano_stake_distribution_for_latest_epoch =
      await client.get_cardano_stake_distribution_for_latest_epoch();
    console.log(
      "cardano_stake_distribution for latest epoch",
      cardano_stake_distribution_for_latest_epoch,
    );
  });

  test_number++;
  await run_test(
    "get_cardano_stake_distribution_for_latest_epoch_with_offset",
    test_number,
    async () => {
      let cardano_stake_distribution_for_latest_epoch_with_offset =
        await client.get_cardano_stake_distribution_for_latest_epoch({ offset: 2 });
      console.log(
        "cardano_stake_distribution for latest epoch with offset",
        cardano_stake_distribution_for_latest_epoch_with_offset,
      );
    },
  );

  let certificate;
  test_number++;
  await run_test("get_mithril_certificate", test_number, async () => {
    certificate = await client.get_mithril_certificate(cardano_stake_distribution.certificate_hash);
    console.log("certificate", certificate);
  });

  let last_certificate_from_chain;
  test_number++;
  await run_test("verify_certificate_chain", test_number, async () => {
    last_certificate_from_chain = await client.verify_certificate_chain(certificate.hash);
    console.log("last_certificate_from_chain", last_certificate_from_chain);
  });

  let cardano_stake_distribution_message;
  test_number++;
  await run_test("compute_cardano_stake_distribution_message", test_number, async () => {
    cardano_stake_distribution_message = await client.compute_cardano_stake_distribution_message(
      certificate,
      cardano_stake_distribution,
    );
    console.log("cardano_stake_distribution_message", cardano_stake_distribution_message);
  });

  test_number++;
  await run_test("verify_message_match_certificate", test_number, async () => {
    const valid_cardano_stake_distribution_message = await client.verify_message_match_certificate(
      cardano_stake_distribution_message,
      last_certificate_from_chain,
    );
    console.log(
      "valid_cardano_stake_distribution_message",
      valid_cardano_stake_distribution_message,
    );
  });
}

if (aggregator_capabilities.includes("CardanoDatabase")) {
  let cardano_database_snapshots;
  test_number++;
  await run_test("list_cardano_database_v2", test_number, async () => {
    cardano_database_snapshots = await client.list_cardano_database_v2();
    console.log("cardano_database_snapshots", cardano_database_snapshots);
  });

  test_number++;
  await run_test("list_cardano_database_v2_per_epoch", test_number, async () => {
    let epoch = BigInt(cardano_database_snapshots[0].beacon.epoch);
    const cardano_database_snapshots_per_epoch =
      await client.list_cardano_database_v2_per_epoch(epoch);
    console.log("cardano_database_snapshots for epoch", cardano_database_snapshots_per_epoch);
  });

  test_number++;
  await run_test("list_cardano_database_v2_for_latest_epoch", test_number, async () => {
    const cardano_database_snapshots_for_latest_epoch =
      await client.list_cardano_database_v2_for_latest_epoch();
    console.log(
      "cardano_database_snapshots for latest epoch",
      cardano_database_snapshots_for_latest_epoch,
    );
  });

  test_number++;
  await run_test("list_cardano_database_v2_for_latest_epoch_with_offset", test_number, async () => {
    const cardano_database_snapshots_for_latest_epoch_with_offset =
      await client.list_cardano_database_v2_for_latest_epoch({ offset: 3 });
    console.log(
      "cardano_database_snapshots for latest epoch with offset",
      cardano_database_snapshots_for_latest_epoch_with_offset,
    );
  });

  let cardano_database_snapshot;
  test_number++;
  await run_test("get_cardano_database_v2", test_number, async () => {
    cardano_database_snapshot = await client.get_cardano_database_v2(
      cardano_database_snapshots[0].hash,
    );
    console.log("cardano_database_snapshot", cardano_database_snapshot);
  });
}

add_finished_div();
