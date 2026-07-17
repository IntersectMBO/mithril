use std::collections::BTreeMap;

/// ImmutableFileNumber represents the id of immutable files in the Cardano node database
pub type ImmutableFileNumber = u64;

/// ImmutableFileName represents the filename, with extension, of a immutable file in the Cardano node database
pub type ImmutableFileName = String;

/// PartyId represents a signing party in Mithril protocol
pub type PartyId = String;

/// Stake represents the stakes of a participant in the Cardano chain
pub type Stake = u64;

/// StakeDistribution represents the stakes of multiple participants in the Cardano chain
pub type StakeDistribution = BTreeMap<PartyId, Stake>;

/// LotteryIndex represents the index of a Mithril single signature lottery
pub type LotteryIndex = u64;

/// Cardano Network magic identifier
pub type MagicId = u64;

/// Protocol version
pub type ProtocolVersion = String;

/// Hex encoded key
pub type HexEncodedKey = String;

/// Hex encoded key slice
pub type HexEncodedKeySlice<'a> = &'a str;

/// Hex encoded Single Signature
pub type HexEncodedSingleSignature = HexEncodedKey;

/// Hex encoded Aggregate Verification Key
pub type HexEncodedAggregateVerificationKey = HexEncodedKey;

/// Hex encoded Verification Key for Concatenation
pub type HexEncodedVerificationKeyForConcatenation = HexEncodedKey;

/// Hex encoded Verification Key Signature for Concatenation
pub type HexEncodedVerificationKeySignatureForConcatenation = HexEncodedKey;

/// Hex encoded Verification Key for SNARK
pub type HexEncodedVerificationKeyForSnark = HexEncodedKey;

/// Hex encoded Verification Key Signature for SNARK
pub type HexEncodedVerificationKeySignatureForSnark = HexEncodedKey;

/// Hex encoded Operational Certificate
pub type HexEncodedOpCert = HexEncodedKey;

/// Hex encoded Genesis Secret Key
pub type HexEncodedGenesisSecretKey = HexEncodedKey;

/// Hex encoded Genesis Verification Key
pub type HexEncodedGenesisVerificationKey = HexEncodedKey;

/// Hex encoded Sha256 Digest
pub type HexEncodedDigest = HexEncodedKey;

/// Hex encoded Era Markers Secret Key
pub type HexEncodedEraMarkersSecretKey = HexEncodedKey;

/// Hex encoded Protocol Configuration Markers Secret Key
pub type HexEncodedProtocolConfigurationMarkersSecretKey = HexEncodedKey;

/// Number of SPOs
pub type TotalSPOs = u32;

/// Cardano Era
pub type CardanoEra = String;
