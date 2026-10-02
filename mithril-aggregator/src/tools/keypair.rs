use std::path::{Path, PathBuf};

use mithril_common::{StdResult, crypto_helper::ed25519::Ed25519Signer};

/// Utilities for generating cryptographic keypairs.
pub struct KeypairTools {}

impl KeypairTools {
    /// Export the ed25519 keypair to a folder and returns the paths to the files (secret key, verification_key)
    pub fn create_and_save_ed25519_keypair(keypair_path: &Path) -> StdResult<(PathBuf, PathBuf)> {
        let secret_key_path = keypair_path.join("ed25519_keypair.sk");
        let verification_key_path = keypair_path.join("ed25519_keypair.vk");

        let signer = Ed25519Signer::create_non_deterministic_signer();
        signer.secret_key().write_json_hex_to_file(&secret_key_path)?;
        signer
            .verification_key()
            .write_json_hex_to_file(&verification_key_path)?;

        Ok((secret_key_path, verification_key_path))
    }
}

#[cfg(test)]
mod tests {
    use mithril_common::{
        crypto_helper::ed25519::{Ed25519SecretKey, Ed25519VerificationKey},
        temp_dir_create,
    };
    use std::fs::read_to_string;

    use super::*;

    #[test]
    fn writes_a_verifiable_ed25519_keypair() {
        let temp_dir = temp_dir_create!();
        let (secret_key_path, verification_key_path) =
            KeypairTools::create_and_save_ed25519_keypair(&temp_dir)
                .expect("Failed to create and save ed25519 keypair");
        let secret_key = Ed25519SecretKey::from_json_hex(
            &read_to_string(&secret_key_path).expect("Failed to read secret key file"),
        )
        .expect("Failed to parse secret key");

        let verification_key = Ed25519VerificationKey::from_json_hex(
            &read_to_string(&verification_key_path).expect("Failed to read verification key file"),
        )
        .expect("Failed to parse verification key");
        let verifier = Ed25519Signer::from_secret_key(secret_key).create_verifier();

        let expected_verification_key = verifier.to_verification_key();
        assert_eq!(expected_verification_key, verification_key);
    }
}
