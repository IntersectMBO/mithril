use kes_summed_ed25519::{PublicKey as KesPublicKey, kes::Sum6Kes, traits::KesSk};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

#[cfg(feature = "future_snark")]
use crate::entities::Epoch;
use crate::{
    crypto_helper::{ColdKeyGenerator, KesPeriod, OpCert, ProtocolStakeDistribution, Sum6KesBytes},
    entities::{PartyId, ProtocolParameters, Stake, StakeDistribution},
    test::{
        builder::MithrilFixture,
        crypto_helper::{self, SerDeShelleyFileFormatTestExtension},
        double::{fake_data, precomputed_kes_key},
    },
};

/// A builder of mithril types.
pub struct MithrilFixtureBuilder {
    protocol_parameters: ProtocolParameters,
    enable_signers_certification: bool,
    number_of_signers: usize,
    stake_distribution_generation_method: StakeDistributionGenerationMethod,
    party_id_seed: [u8; 32],
    #[cfg(feature = "future_snark")]
    epoch: Epoch,
}

impl Default for MithrilFixtureBuilder {
    fn default() -> Self {
        Self {
            protocol_parameters: fake_data::protocol_parameters(),
            enable_signers_certification: true,
            number_of_signers: 5,
            stake_distribution_generation_method:
                StakeDistributionGenerationMethod::RandomDistribution {
                    seed: [0u8; 32],
                    min_stake: 1,
                },
            party_id_seed: [0u8; 32],
            #[cfg(feature = "future_snark")]
            epoch: Epoch::default(),
        }
    }
}

/// Methods that can be used to generate the stake distribution.
pub enum StakeDistributionGenerationMethod {
    /// Each party will have a random stake.
    RandomDistribution {
        /// The randomizer seed
        seed: [u8; 32],
        /// The minimum stake
        min_stake: Stake,
    },

    /// Use a custom stake distribution
    ///
    /// Important: this will overwrite the number of signers set by with_signers.
    Custom(StakeDistribution),

    /// Make a stake distribution where all parties will have the given stake
    Uniform(Stake),
}

impl MithrilFixtureBuilder {
    /// Set the protocol_parameters.
    pub fn with_protocol_parameters(mut self, protocol_parameters: ProtocolParameters) -> Self {
        self.protocol_parameters = protocol_parameters;
        self
    }

    /// Set the number of signers that will be generated.
    pub fn with_signers(mut self, number_of_signers: usize) -> Self {
        self.number_of_signers = number_of_signers;
        self
    }

    /// If set the generated signers won't be certified (meaning that they won't
    /// have a operational certificate).
    pub fn disable_signers_certification(mut self) -> Self {
        self.enable_signers_certification = false;
        self
    }

    /// Set the generation method used to compute the stake distribution.
    pub fn with_stake_distribution(
        mut self,
        stake_distribution_generation_method: StakeDistributionGenerationMethod,
    ) -> Self {
        self.stake_distribution_generation_method = stake_distribution_generation_method;
        self
    }

    /// Set the seed used to generated the party ids
    pub fn with_party_id_seed(mut self, seed: [u8; 32]) -> Self {
        self.party_id_seed = seed;
        self
    }

    /// Set the seed used to generated the party ids
    #[cfg(feature = "future_snark")]
    pub fn with_epoch(mut self, epoch: Epoch) -> Self {
        self.epoch = epoch;
        self
    }

    /// Transform the specified parameters to a [MithrilFixture].
    pub fn build(self) -> MithrilFixture {
        let protocol_stake_distribution = self.generate_stake_distribution();
        let signers = crypto_helper::setup_signers_from_stake_distribution(
            &protocol_stake_distribution,
            &self.protocol_parameters.clone().into(),
            #[cfg(feature = "future_snark")]
            self.epoch,
        );

        MithrilFixture::new(
            self.protocol_parameters,
            signers,
            protocol_stake_distribution,
            #[cfg(feature = "future_snark")]
            self.epoch,
        )
    }

    fn generate_stake_distribution(&self) -> ProtocolStakeDistribution {
        let signers_party_ids = self.generate_party_ids();

        match &self.stake_distribution_generation_method {
            StakeDistributionGenerationMethod::RandomDistribution { seed, min_stake } => {
                let mut stake_rng = ChaCha20Rng::from_seed(*seed);

                signers_party_ids
                    .into_iter()
                    .map(|party_id| {
                        let stake = min_stake + stake_rng.next_u64() % 999;
                        (party_id, stake)
                    })
                    .collect::<Vec<_>>()
            }
            StakeDistributionGenerationMethod::Custom(stake_distribution) => stake_distribution
                .clone()
                .into_iter()
                .collect::<ProtocolStakeDistribution>(),
            StakeDistributionGenerationMethod::Uniform(stake) => signers_party_ids
                .into_iter()
                .map(|party_id| (party_id, *stake))
                .collect::<ProtocolStakeDistribution>(),
        }
    }

    fn generate_party_ids(&self) -> Vec<PartyId> {
        match self.stake_distribution_generation_method {
            StakeDistributionGenerationMethod::Custom(_) => vec![],
            _ => {
                let signers_party_ids = (0..self.number_of_signers).map(|party_index| {
                    if self.enable_signers_certification {
                        self.build_party_with_operational_certificate(party_index)
                    } else {
                        party_index.to_string()
                    }
                });
                signers_party_ids.collect::<Vec<_>>()
            }
        }
    }

    fn provide_kes_key(kes_key_seed: &mut [u8]) -> (Sum6KesBytes, KesPublicKey) {
        if let Some((kes_bytes, kes_verification_key)) =
            MithrilFixtureBuilder::cached_kes_key(kes_key_seed)
        {
            (kes_bytes, kes_verification_key)
        } else {
            println!(
                "KES key not found in test cache, generating a new one for the seed {kes_key_seed:?}."
            );
            MithrilFixtureBuilder::generate_kes_key(kes_key_seed)
        }
    }

    fn cached_kes_key(kes_key_seed: &[u8]) -> Option<(Sum6KesBytes, KesPublicKey)> {
        precomputed_kes_key::cached_kes_key(kes_key_seed).map(
            |(kes_bytes, kes_verification_key)| {
                let kes_verification_key = KesPublicKey::from_bytes(&kes_verification_key).unwrap();
                let kes_bytes = Sum6KesBytes(kes_bytes);

                (kes_bytes, kes_verification_key)
            },
        )
    }

    fn generate_kes_key(kes_key_seed: &mut [u8]) -> (Sum6KesBytes, KesPublicKey) {
        let mut key_buffer = [0u8; Sum6Kes::SIZE + 4];

        let (kes_secret_key, kes_verification_key) = Sum6Kes::keygen(&mut key_buffer, kes_key_seed);
        let mut kes_bytes = Sum6KesBytes([0u8; Sum6Kes::SIZE + 4]);
        kes_bytes.0.copy_from_slice(&kes_secret_key.clone_sk());

        (kes_bytes, kes_verification_key)
    }

    fn generate_cold_key_seed(&self, party_index: usize) -> Vec<u8> {
        let mut cold_key_seed: Vec<_> = (party_index)
            .to_le_bytes()
            .iter()
            .zip(self.party_id_seed)
            .map(|(v1, v2)| v1 + v2)
            .collect();
        cold_key_seed.resize(32, 0);

        cold_key_seed
    }

    fn build_party_with_operational_certificate(&self, party_index: usize) -> PartyId {
        let cold_key_seed = self.generate_cold_key_seed(party_index).to_vec();
        let mut kes_key_seed = cold_key_seed.clone();

        let keypair =
            ColdKeyGenerator::create_deterministic_keypair(cold_key_seed.try_into().unwrap());
        let (kes_bytes, kes_verification_key) =
            MithrilFixtureBuilder::provide_kes_key(&mut kes_key_seed);
        let operational_certificate = OpCert::new(kes_verification_key, 0, KesPeriod(0), keypair);
        let party_id = operational_certificate
            .compute_protocol_party_id()
            .expect("compute protocol party id should not fail");
        let temp_dir = crypto_helper::setup_temp_directory_for_signer(&party_id, true)
            .expect("setup temp directory should return a value");
        if !temp_dir.join("kes.sk").exists() {
            kes_bytes
                .to_file(temp_dir.join("kes.sk"))
                .expect("KES secret key file export should not fail");
        }
        if !temp_dir.join("opcert.cert").exists() {
            operational_certificate
                .to_file(temp_dir.join("opcert.cert"))
                .expect("operational certificate file export should not fail");
        }
        party_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn with_protocol_params() {
        let protocol_parameters = ProtocolParameters::new(1, 10, 0.56);
        let result = MithrilFixtureBuilder::default()
            .with_protocol_parameters(protocol_parameters.clone())
            .build();

        assert_eq!(protocol_parameters, result.protocol_parameters());
    }

    #[test]
    fn with_signers() {
        let result = MithrilFixtureBuilder::default().with_signers(4).build();

        assert_eq!(4, result.signers_with_stake().len());
    }

    #[test]
    fn random_stake_distribution_generates_as_many_signers_as_parties() {
        let result = MithrilFixtureBuilder::default()
            .with_stake_distribution(StakeDistributionGenerationMethod::RandomDistribution {
                seed: [0u8; 32],
                min_stake: 1,
            })
            .with_signers(4)
            .build();

        assert_eq!(4, result.stake_distribution().len());
    }

    #[test]
    fn uniform_stake_distribution() {
        let expected_stake = 10;
        let stake_distribution = MithrilFixtureBuilder::default()
            .with_stake_distribution(StakeDistributionGenerationMethod::Uniform(expected_stake))
            .with_signers(5)
            .build()
            .stake_distribution();

        assert!(
            stake_distribution.iter().all(|(_, stake)| *stake == expected_stake),
            "Generated stake distribution doesn't have uniform stakes: {stake_distribution:?}"
        );
    }

    #[test]
    fn each_parties_generated_with_random_stake_distribution_have_different_stakes() {
        let result = MithrilFixtureBuilder::default()
            .with_stake_distribution(StakeDistributionGenerationMethod::RandomDistribution {
                seed: [0u8; 32],
                min_stake: 1,
            })
            .with_signers(5)
            .build();
        let stakes = result.stake_distribution();

        // BtreeSet dedup values
        assert_eq!(stakes.len(), BTreeSet::from_iter(stakes.values()).len());
    }

    #[test]
    fn dont_generate_party_ids_for_custom_stake_distribution() {
        let stake_distribution = StakeDistribution::from_iter([("party".to_owned(), 4)]);
        let builder = MithrilFixtureBuilder::default()
            .with_stake_distribution(StakeDistributionGenerationMethod::Custom(
                stake_distribution,
            ))
            .with_signers(5);

        assert_eq!(Vec::<PartyId>::new(), builder.generate_party_ids());
    }

    #[test]
    fn changing_party_id_seed_change_all_builded_party_ids() {
        let first_signers = MithrilFixtureBuilder::default()
            .with_signers(10)
            .build()
            .signers_with_stake();
        let different_party_id_seed_signers = MithrilFixtureBuilder::default()
            .with_signers(10)
            .with_party_id_seed([1u8; 32])
            .build()
            .signers_with_stake();
        let first_party_ids: Vec<&PartyId> = first_signers.iter().map(|s| &s.party_id).collect();

        for party_id in different_party_id_seed_signers.iter().map(|s| &s.party_id) {
            assert!(!first_party_ids.contains(&party_id));
        }
    }

    /// Verify that there is a cached kes key for a number of party id.
    /// If the cache is not up to date, the test will generate the code that can be copied/pasted into the [precomputed_kes_key] module.
    /// The number of party id that should be in cache is defined with `precomputed_number`
    #[test]
    fn verify_kes_key_cache_content() {
        // Generate code that should be in the `cached_kes_key` function of the `precomputed_kes_key.rs` file.
        // It can be copied and pasted to update the cache.
        fn generate_code(party_ids: &Vec<(&[u8], [u8; 612], KesPublicKey)>) -> String {
            party_ids
                .iter()
                .map(|(key, i, p)| format!("{:?} => ({:?}, {:?}),", key, i, p.as_bytes()))
                .collect::<Vec<_>>()
                .join("\n")
        }

        let precomputed_number = 10;

        let fixture = MithrilFixtureBuilder::default();
        let cold_keys: Vec<_> = (0..precomputed_number)
            .map(|party_index| fixture.generate_cold_key_seed(party_index))
            .collect();

        let computed_keys_key: Vec<_> = cold_keys
            .iter()
            .map(|cold_key| {
                let mut kes_key_seed: Vec<u8> = cold_key.clone();
                let (kes_bytes, kes_verification_key) =
                    MithrilFixtureBuilder::generate_kes_key(&mut kes_key_seed);

                (cold_key.as_slice(), kes_bytes.0, kes_verification_key)
            })
            .collect();

        let cached_kes_key: Vec<_> = cold_keys
            .iter()
            .filter_map(|cold_key| {
                MithrilFixtureBuilder::cached_kes_key(cold_key).map(
                    |(kes_bytes, kes_verification_key)| {
                        (cold_key.as_slice(), kes_bytes.0, kes_verification_key)
                    },
                )
            })
            .collect();

        let expected_code = generate_code(&computed_keys_key);
        let actual_code = generate_code(&cached_kes_key);

        assert_eq!(
            computed_keys_key, cached_kes_key,
            "Precomputed KES keys should be:\n{expected_code}\nbut seems to be:\n{actual_code}"
        );

        let kes_key_seed = fixture.generate_cold_key_seed(precomputed_number);
        assert!(
            MithrilFixtureBuilder::cached_kes_key(kes_key_seed.as_slice()).is_none(),
            "We checked precomputed KES keys up to {precomputed_number} but it seems to be more."
        );
    }
}
