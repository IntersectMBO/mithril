use std::sync::Arc;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

use mithril_stm::{Parameters, SchnorrSigningKey};

use crate::StdResult;
use crate::crypto_helper::{
    KesEvolutions, KesPeriod, KesSignerStandard, OpCert, ProtocolInitializer,
    SerDeShelleyFileFormat,
};
use crate::entities::{Epoch, SignerWithStake, Stake};

use super::{
    KesCryptographicMaterialForTest, KesPartyIndexForTest, ProtocolInitializerTestExtension,
    create_kes_cryptographic_material,
};

/// `TEST ONLY` - Build two [SignerWithStake], each with its own valid opcert/KES material/pool_id,
/// that share the same underlying SNARK Schnorr signing key.
///
/// Simulates two SPOs (accidentally or maliciously) sharing one signing key — used to test
/// SNARK-vk deduplication (a single shared key must not let its holder(s) claim two independent
/// stake-weighted registrations).
pub fn create_signers_with_stake_sharing_snark_key(
    stakes: [Stake; 2],
    epoch: Epoch,
    test_directory: &str,
) -> StdResult<[SignerWithStake; 2]> {
    let params = Parameters {
        m: 5,
        k: 5,
        phi_f: 1.0,
    };
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    let shared_schnorr_signing_key = SchnorrSigningKey::generate(&mut rng);

    let signers = stakes
        .into_iter()
        .enumerate()
        .map(|(index, stake)| {
            let KesCryptographicMaterialForTest {
                party_id,
                operational_certificate_file,
                kes_secret_key_file,
            } = create_kes_cryptographic_material(
                (index + 1) as KesPartyIndexForTest,
                KesPeriod(0),
                test_directory,
            );

            let initializer = ProtocolInitializer::setup_with_shared_schnorr_key(
                params,
                Some(Arc::new(KesSignerStandard::new(
                    kes_secret_key_file,
                    operational_certificate_file.clone(),
                ))),
                Some(KesPeriod(0)),
                stake,
                epoch,
                shared_schnorr_signing_key.clone(),
                &mut rng,
            )?;

            let operational_certificate = OpCert::from_file(operational_certificate_file)
                .expect("opcert deserialization should not fail")
                .into();

            Ok(SignerWithStake {
                party_id,
                verification_key_for_concatenation: initializer
                    .verification_key_for_concatenation()
                    .into(),
                verification_key_signature_for_concatenation: initializer
                    .verification_key_signature_for_concatenation(),
                operational_certificate: Some(operational_certificate),
                kes_evolutions: Some(KesEvolutions(0)),
                stake,
                verification_key_for_snark: initializer
                    .verification_key_for_snark()
                    .map(Into::into),
                verification_key_signature_for_snark: initializer
                    .verification_key_signature_for_snark(),
                proof_of_bound_possession_for_snark: initializer
                    .proof_of_bound_possession_for_snark(),
            })
        })
        .collect::<StdResult<Vec<_>>>()?;

    Ok(signers
        .try_into()
        .expect("exactly two stakes were provided, so exactly two signers are built"))
}
