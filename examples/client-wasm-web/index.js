import initMithrilClient, { MithrilClient } from "@mithril-dev/mithril-client-wasm";

// This example uses 'release-preprod' network aggregator as it handles Cardano transactions entity type
let aggregator_endpoint = "https://aggregator.release-preprod.api.mithril.network/aggregator";
let genesis_verification_key =
  "5b3132372c37332c3132342c3136312c362c3133372c3133312c3231332c3230372c3131372c3139382c38352c3137362c3139392c3136322c3234312c36382c3132332c3131392c3134352c31332c3233322c3234332c34392c3232392c322c3234392c3230352c3230352c33392c3233352c34345d";
let certificate_chain_validated_occurs = false;
const broadcast_channel = new BroadcastChannel("mithril-client");
broadcast_channel.onmessage = (e) => {
  let event = e.data;
  if (event.type == "CertificateChainValidationStarted") {
    displayMessageInDOM(
      event.type,
      "The certificate chain validation has started, event_id: " +
        event.payload.certificate_chain_validation_id,
    );
  } else if (event.type == "CertificateValidated") {
    displayMessageInDOM(
      event.type,
      "A certificate has been validated, certificate_hash: " +
        event.payload.certificate_hash +
        ", event_id: " +
        event.payload.certificate_chain_validation_id,
    );
  } else if (event.type == "CertificateFetchedFromCache") {
    displayMessageInDOM(
      event.type,
      "A certificate has been fetched from the cache, certificate_hash: " +
        event.payload.certificate_hash +
        ", event_id: " +
        event.payload.certificate_chain_validation_id,
    );
  } else if (event.type == "CertificateChainValidated") {
    certificate_chain_validated_occurs = true;
    displayMessageInDOM(
      event.type,
      "The certificate chain is valid, event_id: " + event.payload.certificate_chain_validation_id,
    );
  } else {
    displayMessageInDOM(event);
  }
};

async function waitUntilCertificateChainValidatedOccursOrTimeout() {
  for (let i = 0; i < 100 && !certificate_chain_validated_occurs; i++) {
    await new Promise((r) => setTimeout(r, 100));
  }
  certificate_chain_validated_occurs = false;
}

function displayMessageInDOM(subject, message) {
  let div = document.createElement("div");
  div.innerHTML = "<strong>" + subject + ": </strong>" + message;
  document.body.appendChild(div);
  window.scrollTo(0, document.body.scrollHeight);
  console.log(message);
}

function displayStepInDOM(number, content) {
  let div = document.createElement("div");
  div.innerHTML =
    '<h2><span style="color: green;"> Step n°' +
    number +
    ": </span></h2>" +
    "<i>" +
    content +
    "<i>";
  document.body.appendChild(div);
}

function format_tx_list(transactions_hashes) {
  return "<ul>" + transactions_hashes.map((tx) => "<li>" + tx + "</li>").join("") + "</ul>";
}

await initMithrilClient();

let client_options = {
  // The following header is set as an example.
  // It's used to demonstrate how to add headers.
  http_headers: new Map([["Content-Type", "application/json"]]),
  // The 'origin_tag' option is an identifier used by the aggregator to track the source of requests.
  origin_tag: "EXAMPLE",
  // The following option activates the certificate chain cache, stored in IndexedDB.
  // The verified certificates are reused by the next certificate chain verifications, even after a page reload.
  enable_certificate_chain_verification_cache: true,
  // The chain verification stops at the first cached certificate ('EarlyStopVerification', the default),
  // or re-verifies the cached certificates ('FullVerification').
  certificate_chain_verification_cache_mode: "EarlyStopVerification",
};
let client = new MithrilClient(aggregator_endpoint, genesis_verification_key, client_options);
displayMessageInDOM(
  "Certificate chain cache enabled",
  await client.is_certificate_verifier_cache_enabled(),
);

displayStepInDOM(1, "Getting stake distributions list...");
let mithril_stake_distributions_list = await client.list_mithril_stake_distributions();
displayMessageInDOM(
  "Result",
  "got " + mithril_stake_distributions_list.length + " stake distributions &#x2713;",
);
console.log("stake distributions:", mithril_stake_distributions_list);

let last_mithril_stake_distribution = mithril_stake_distributions_list[0];
console.log("last_mithril_stake_distribution:", last_mithril_stake_distribution);

displayStepInDOM(
  2,
  "Getting last stake distribution with hash: " + last_mithril_stake_distribution.hash + "...",
);
let last_stake_distribution = await client.get_mithril_stake_distribution(
  last_mithril_stake_distribution.hash,
);
displayMessageInDOM("Result", "got last stake distribution &#x2713;");
console.log("last_stake_distribution:", last_stake_distribution);

displayStepInDOM(
  3,
  "Getting Mithril certificate from certificate hash: " +
    last_stake_distribution.certificate_hash +
    "...",
);
let certificate = await client.get_mithril_certificate(last_stake_distribution.certificate_hash);
displayMessageInDOM("Result", "got Mithril certificate &#x2713;");
console.log("certificate:", certificate);

displayStepInDOM(4, "Verifying certificate chain...");
let last_certificate_from_chain = await client.verify_certificate_chain(certificate.hash);
await waitUntilCertificateChainValidatedOccursOrTimeout();
displayMessageInDOM("Result", "certificate chain verified &#x2713;");
console.log(
  "verify_certificate_chain OK, last_certificate_from_chain:",
  last_certificate_from_chain,
);

displayStepInDOM(5, "Computing the Mithril stake distribution message...");
let mithril_stake_distributions_message = await client.compute_mithril_stake_distribution_message(
  last_stake_distribution,
  last_certificate_from_chain,
);
displayMessageInDOM("Result", "Mithril stake distribution message computed &#x2713;");
console.log("mithril_stake_distributions_message:", mithril_stake_distributions_message);

displayStepInDOM(6, "Validating Mithril stake distribution message...");
let valid_stake_distribution_message = await client.verify_message_match_certificate(
  mithril_stake_distributions_message,
  last_certificate_from_chain,
);
displayMessageInDOM("Result", "Mithril stake distribution message validated &#x2713;");
console.log("valid_stake_distribution_message:", valid_stake_distribution_message);

displayStepInDOM(7, "Getting transaction proof...");
const proof = await client.get_cardano_transaction_proofs([
  "0ea207ab71493f012faab0d1f8151eaf931901141c1482ce6e9a501498076484",
  "326b5b67d926937bf19c6113d0957a39f2eae9df94875ce8a96eff5c8521303b",
  "320c13f4a3e51f6f4f66fcd9007e02bf658aa4ee9a88a509028d867d3b8a8e9a",
]);
displayMessageInDOM("Certificate hash of the returned proof", proof.certificate_hash);
displayMessageInDOM(
  "Transactions hashes included in the proof",
  format_tx_list(proof.transactions_hashes),
);
displayMessageInDOM(
  "Transactions hashes not included in the proof",
  format_tx_list(proof.non_certified_transactions),
);

displayStepInDOM(9, "Verifying certificate chain...");
let proof_certificate = await client.verify_certificate_chain(proof.certificate_hash);
await waitUntilCertificateChainValidatedOccursOrTimeout();
displayMessageInDOM("Result", "certificate chain verified &#x2713;");
console.log("verify_certificate_chain OK, last_certificate_from_chain:", proof_certificate);

displayStepInDOM(10, "Validating Cardano transaction proof message...");
let protocol_message = await client.verify_cardano_transaction_proof_then_compute_message(
  proof,
  proof_certificate,
);
console.log("Ensuire that the proof is indeed signed in the associated certificate");
if ((await client.verify_message_match_certificate(protocol_message, proof_certificate)) === true) {
  displayMessageInDOM("Result", "The proof is signed in the associated certificate &#x2713;");
} else {
  displayMessageInDOM("Result", "Proof and certificate don't match &#x2717;");
}
displayMessageInDOM("Transactions hashes certified", format_tx_list(proof.transactions_hashes));
displayMessageInDOM(
  "Transactions hashes not certified",
  format_tx_list(proof.non_certified_transactions),
);
