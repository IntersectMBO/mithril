use crate::crypto_helper::ed25519::*;

pub mod era {
    use super::*;

    /// Era markers verifier secret key
    pub type EraMarkersVerifierSecretKey = Ed25519SecretKey;
    /// Era markers verifier verification key
    pub type EraMarkersVerifierVerificationKey = Ed25519VerificationKey;
    /// Era markers verifier signature
    pub type EraMarkersVerifierSignature = Ed25519Signature;
    /// A cryptographic signer that is responsible for signing the EraMarkers
    pub type EraMarkersSigner = Ed25519Signer;
    /// An era markers verifier that checks the authenticity of era markers stored on the chain
    pub type EraMarkersVerifier = Ed25519Verifier;
    /// [EraMarkersSigner] and [EraMarkersVerifier] related errors.
    pub type EraMarkersVerifierError = Ed25519VerifierError;

    /// Protocol Configuration markers verifier secret key
    pub type ProtocolConfigurationMarkersVerifierSecretKey = Ed25519SecretKey;
    /// Protocol Configuration markers verifier verification key
    pub type ProtocolConfigurationMarkersVerifierVerificationKey = Ed25519VerificationKey;
    /// Protocol Configuration markers verifier signature
    pub type ProtocolConfigurationMarkersVerifierSignature = Ed25519Signature;
    /// A cryptographic signer that is responsible for signing the ProtocolConfigurationMarkers
    pub type ProtocolConfigurationMarkersSigner = Ed25519Signer;
}

pub mod manifest {
    use super::*;

    /// Manifest verifier secret key
    pub type ManifestVerifierSecretKey = Ed25519SecretKey;
    /// Manifest verifier verification key
    pub type ManifestVerifierVerificationKey = Ed25519VerificationKey;
    /// Manifest signature
    pub type ManifestSignature = Ed25519Signature;
    /// A cryptographic signer that is responsible for signing the Manifest
    pub type ManifestSigner = Ed25519Signer;
    /// A manifest verifier that checks the authenticity of a manifest
    pub type ManifestVerifier = Ed25519Verifier;
    /// [ManifestSigner] and [ManifestVerifier] related errors.
    pub type ManifestVerifierError = Ed25519VerifierError;
}
