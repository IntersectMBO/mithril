//! Filesystem asset writers for the recursive Halo2 IVC golden generators.
//!
//! The read-only, embedded asset layer (typed representations, `include_bytes!` constants, and
//! byte decoders) lives in [`crate::circuits::halo2_ivc::embedded_assets`] so the IVC benchmarks
//! can share it. This module keeps the test-only asset-writing infrastructure (the `store_*`
//! functions used by the golden generators) and re-exports the embedded types and loaders so the
//! `tests::common::asset_readers::{...}` import paths continue to resolve unchanged.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufWriter, Write},
    path::Path,
};

use anyhow::Context;
use midnight_proofs::utils::{SerdeFormat, helpers::ProcessedSerdeObject};

use crate::StmResult;
use crate::circuits::halo2_ivc::{
    Accumulator, EmulatedCurve, NativeField, PREIMAGE_SIZE, RecursiveEmulation,
    io::Write as IvcWrite,
    state::State,
    types::{CertificateProofBytes, IvcProofBytes},
};
use crate::signature_scheme::StandardSchnorrSignature;

pub(crate) use crate::circuits::halo2_ivc::embedded_assets::{
    FirstCertificateInEpochAsset, FollowingCertificateInEpochAsset, GenesisStepOutputAsset,
    NextEpochStepOutputAsset, RecursiveChainStateAsset, StepOutputAsset, VerificationContextAsset,
    load_embedded_first_certificate_in_epoch_asset,
    load_embedded_following_certificate_in_epoch_asset, load_embedded_genesis_step_output_asset,
    load_embedded_next_epoch_step_output_asset, load_embedded_recursive_chain_state_asset,
    load_embedded_verification_context_asset, load_recursive_chain_state_asset,
};

/// Creates a golden asset file and its parent directory if needed.
fn create_asset_file(path: &Path) -> StmResult<BufWriter<File>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(BufWriter::new(File::create(path)?))
}

/// Writes one field element as 32 little-endian bytes.
fn write_field_element<W: Write>(writer: &mut W, value: &NativeField) -> StmResult<()> {
    writer.write_all(&value.to_bytes_le())?;
    Ok(())
}

/// Writes the seven public-input field elements of a recursive state.
fn write_state_public_input<W: Write>(writer: &mut W, state: &State) -> StmResult<()> {
    for value in state.as_public_input() {
        write_field_element(writer, &value)?;
    }
    Ok(())
}

/// Writes a 64-byte `StandardSchnorrSignature` (response | challenge).
fn write_schnorr_signature<W: Write>(
    writer: &mut W,
    signature: &StandardSchnorrSignature,
) -> StmResult<()> {
    writer.write_all(&signature.to_bytes())?;
    Ok(())
}

/// Writes proof bytes with a 32-bit little-endian length prefix.
fn write_length_prefixed_proof<W: Write>(writer: &mut W, proof: &[u8]) -> StmResult<()> {
    writer.write_all(&(proof.len() as u32).to_le_bytes())?;
    writer.write_all(proof)?;
    Ok(())
}

/// Writes the named fixed-base map stored in the verification-context asset.
fn write_named_fixed_bases<W: Write>(
    writer: &mut W,
    fixed_bases: &BTreeMap<String, EmulatedCurve>,
) -> StmResult<()> {
    writer.write_all(&(fixed_bases.len() as u32).to_le_bytes())?;
    for (name, point) in fixed_bases {
        let name_bytes = name.as_bytes();
        writer.write_all(&(name_bytes.len() as u32).to_le_bytes())?;
        writer.write_all(name_bytes)?;
        point.write(writer, SerdeFormat::RawBytesUnchecked)?;
    }
    Ok(())
}

/// Writes the recursive chain state asset using the committed binary layout.
pub(crate) fn store_recursive_chain_state_asset(
    path: &Path,
    asset: &RecursiveChainStateAsset,
) -> StmResult<()> {
    let mut writer = create_asset_file(path).with_context(|| {
        format!(
            "failed to create recursive chain state asset file: {}",
            path.display()
        )
    })?;

    for value in &asset.global_field_elements {
        write_field_element(&mut writer, value)?;
    }
    write_state_public_input(&mut writer, &asset.state)?;
    write_length_prefixed_proof(&mut writer, asset.ivc_proof.as_bytes())?;
    asset.accumulator.write(&mut writer, SerdeFormat::RawBytesUnchecked)?;
    write_schnorr_signature(&mut writer, &asset.genesis_signature)?;
    writer.flush().with_context(|| {
        format!(
            "failed to flush recursive chain state asset: {}",
            path.display()
        )
    })?;
    Ok(())
}

/// Writes the verification-context asset using the committed binary layout.
///
/// Binary layout (v2): see
/// [`crate::circuits::halo2_ivc::embedded_assets::load_embedded_verification_context_asset`].
pub(crate) fn store_verification_context_asset(
    path: &Path,
    asset: &VerificationContextAsset,
) -> StmResult<()> {
    let mut writer = create_asset_file(path).with_context(|| {
        format!(
            "failed to create verification context asset file: {}",
            path.display()
        )
    })?;

    for value in &asset.global_field_elements {
        write_field_element(&mut writer, value)?;
    }
    asset
        .recursive_verifying_key
        .verifying_key()
        .write(&mut writer, SerdeFormat::RawBytesUnchecked)?;
    write_named_fixed_bases(&mut writer, &asset.combined_fixed_bases)?;

    // Buffer verifier_params to write with a length prefix so the certificate verification key can follow.
    let mut verifier_params_buf = Vec::new();
    asset
        .verifier_params
        .write(&mut verifier_params_buf, SerdeFormat::RawBytesUnchecked)?;
    write_length_prefixed_proof(&mut writer, &verifier_params_buf)?;

    let mut certificate_verification_key_buf = Vec::new();
    asset
        .certificate_verifying_key
        .midnight_vk()
        .write(&mut certificate_verification_key_buf, SerdeFormat::RawBytes)?;
    write_length_prefixed_proof(&mut writer, &certificate_verification_key_buf)?;

    writer.flush().with_context(|| {
        format!(
            "failed to flush verification context asset: {}",
            path.display()
        )
    })?;
    Ok(())
}

/// Writes the step-output common shape using the committed binary layout. Shared
/// across the three step output asset writers.
#[allow(clippy::too_many_arguments)]
fn write_step_output_fields<W: Write>(
    writer: &mut W,
    ivc_proof: &IvcProofBytes,
    next_accumulator: &Accumulator<RecursiveEmulation>,
    next_state: &State,
    certificate_proof: &CertificateProofBytes,
    message: &[u8; 32],
    message_preimage: &[u8; PREIMAGE_SIZE],
    aggregate_verification_key_merkle_root: &[u8; 32],
) -> StmResult<()> {
    write_length_prefixed_proof(writer, ivc_proof.as_bytes())?;
    next_accumulator.write(writer, SerdeFormat::RawBytesUnchecked)?;
    write_state_public_input(writer, next_state)?;
    write_length_prefixed_proof(writer, certificate_proof.as_bytes())?;
    write_length_prefixed_proof(writer, message)?;
    write_length_prefixed_proof(writer, message_preimage)?;
    writer.write_all(aggregate_verification_key_merkle_root)?;
    Ok(())
}

/// Writes the next-epoch step output asset using the committed binary layout.
pub(crate) fn store_next_epoch_step_output_asset(
    path: &Path,
    asset: &NextEpochStepOutputAsset,
) -> StmResult<()> {
    let mut writer = create_asset_file(path).with_context(|| {
        format!(
            "failed to create next-epoch step output asset file: {}",
            path.display()
        )
    })?;
    write_step_output_fields(
        &mut writer,
        &asset.ivc_proof,
        &asset.next_accumulator,
        &asset.next_state,
        &asset.certificate_proof,
        &asset.message,
        &asset.message_preimage,
        &asset.aggregate_verification_key_merkle_root,
    )?;
    writer.flush().with_context(|| {
        format!(
            "failed to flush next-epoch step output asset: {}",
            path.display()
        )
    })?;
    Ok(())
}

/// Writes the genesis step output asset using the committed binary layout.
pub(crate) fn store_genesis_step_output_asset(
    path: &Path,
    asset: &GenesisStepOutputAsset,
) -> StmResult<()> {
    let mut writer = create_asset_file(path).with_context(|| {
        format!(
            "failed to create genesis step output asset file: {}",
            path.display()
        )
    })?;
    write_step_output_fields(
        &mut writer,
        &asset.ivc_proof,
        &asset.next_accumulator,
        &asset.next_state,
        &asset.certificate_proof,
        &asset.message,
        &asset.message_preimage,
        &asset.aggregate_verification_key_merkle_root,
    )?;
    writer.flush().with_context(|| {
        format!(
            "failed to flush genesis step output asset: {}",
            path.display()
        )
    })?;
    Ok(())
}

/// Writes the following-certificate-in-epoch step output asset using the committed
/// binary layout.
pub(crate) fn store_following_certificate_in_epoch_asset(
    path: &Path,
    asset: &FollowingCertificateInEpochAsset,
) -> StmResult<()> {
    let mut writer = create_asset_file(path).with_context(|| {
        format!(
            "failed to create following-certificate-in-epoch asset file: {}",
            path.display()
        )
    })?;
    write_step_output_fields(
        &mut writer,
        &asset.ivc_proof,
        &asset.next_accumulator,
        &asset.next_state,
        &asset.certificate_proof,
        &asset.message,
        &asset.message_preimage,
        &asset.aggregate_verification_key_merkle_root,
    )?;
    writer.flush().with_context(|| {
        format!(
            "failed to flush following-certificate-in-epoch asset: {}",
            path.display()
        )
    })?;
    Ok(())
}

/// Writes the first-certificate-in-epoch asset using the committed binary layout.
pub(crate) fn store_first_certificate_in_epoch_asset(
    path: &Path,
    asset: &FirstCertificateInEpochAsset,
) -> StmResult<()> {
    let mut writer = create_asset_file(path).with_context(|| {
        format!(
            "failed to create first-certificate-in-epoch asset file: {}",
            path.display()
        )
    })?;

    write_length_prefixed_proof(&mut writer, asset.certificate_proof.as_bytes())?;
    write_state_public_input(&mut writer, &asset.next_state)?;
    write_length_prefixed_proof(&mut writer, &asset.message)?;
    write_length_prefixed_proof(&mut writer, &asset.message_preimage)?;
    writer.write_all(&asset.aggregate_verification_key_merkle_root)?;
    writer.flush().with_context(|| {
        format!(
            "failed to flush first-certificate-in-epoch asset: {}",
            path.display()
        )
    })?;
    Ok(())
}
