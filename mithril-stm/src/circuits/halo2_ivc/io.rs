//! Byte serialization of the recursive circuit's rolling accumulator and its MSMs.
//!
//! The `WriteWithFormat` / `ReadWithFormat` traits define the on-the-wire layout.
//! All length prefixes are little-endian `u32`.
//!
//! - `Msm`: `bases.len()` then each base via the format-aware `write` (honours `SerdeFormat`);
//!   `scalars.len()` then each scalar via raw `write_raw`; `fixed_base_scalars.len()` then, per entry,
//!   `key.len()` + the UTF-8 key bytes + the value via raw `write_raw`. Entries follow `BTreeMap` key
//!   order, so the encoding is deterministic.
//! - `Accumulator`: its `lhs` `Msm` followed by its `rhs` `Msm`.

use super::{Accumulator, EmulatedCurve, Msm, NativeField, RecursiveEmulation};
use midnight_curves::serde::SerdeObject;
use midnight_proofs::utils::{SerdeFormat, helpers::ProcessedSerdeObject};
use std::{collections::BTreeMap, io};

pub trait WriteWithFormat {
    fn write<W: io::Write>(&self, w: &mut W, format: SerdeFormat) -> io::Result<()>;
}
pub trait ReadWithFormat: Sized {
    fn read<R: io::Read>(r: &mut R, format: SerdeFormat) -> io::Result<Self>;
}

impl WriteWithFormat for Msm<RecursiveEmulation> {
    fn write<W: io::Write>(&self, writer: &mut W, format: SerdeFormat) -> io::Result<()> {
        let bases = self.bases();
        let scalars = self.scalars();
        let fixed_base_scalars = self.fixed_base_scalars();

        writer.write_all(&(bases.len() as u32).to_le_bytes())?;
        for base in &bases {
            base.write(writer, format)?;
        }

        writer.write_all(&(scalars.len() as u32).to_le_bytes())?;
        for scalar in &scalars {
            scalar.write_raw(writer)?;
        }

        writer.write_all(&(fixed_base_scalars.len() as u32).to_le_bytes())?;
        for (key, value) in &fixed_base_scalars {
            let key_bytes = key.as_bytes();
            writer.write_all(&(key_bytes.len() as u32).to_le_bytes())?;
            writer.write_all(key_bytes)?;
            value.write_raw(writer)?;
        }

        Ok(())
    }
}

impl ReadWithFormat for Msm<RecursiveEmulation> {
    fn read<R: io::Read>(
        reader: &mut R,
        format: SerdeFormat,
    ) -> io::Result<Msm<RecursiveEmulation>> {
        let mut num_bases = [0u8; 4];
        reader.read_exact(&mut num_bases)?;
        let num_bases = u32::from_le_bytes(num_bases);

        let bases: Vec<_> = (0..num_bases)
            .map(|_| EmulatedCurve::read(reader, format))
            .collect::<Result<_, _>>()?;

        let mut num_scalars = [0u8; 4];
        reader.read_exact(&mut num_scalars)?;
        let num_scalars = u32::from_le_bytes(num_scalars);

        // `Msm::new` asserts the two counts agree, so a mismatch has to be rejected here rather
        // than carried into the constructor.
        if num_scalars != num_bases {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("MSM declares {num_bases} bases and {num_scalars} scalars"),
            ));
        }

        let scalars: Vec<_> = (0..num_scalars)
            .map(|_| NativeField::read_raw(reader))
            .collect::<Result<_, _>>()?;

        let mut num_fixed_base_scalars = [0u8; 4];
        reader.read_exact(&mut num_fixed_base_scalars)?;
        let num_fixed_base_scalars = u32::from_le_bytes(num_fixed_base_scalars);

        let mut fixed_base_scalars = BTreeMap::new();
        for _ in 0..num_fixed_base_scalars {
            let mut key_len = [0u8; 4];
            reader.read_exact(&mut key_len)?;
            let key_len = u32::from_le_bytes(key_len);

            let mut key_bytes = vec![0u8; key_len as usize];
            reader.read_exact(&mut key_bytes)?;
            let key = String::from_utf8(key_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid UTF-8 key"))?;

            let value = NativeField::read_raw(reader)?;

            fixed_base_scalars.insert(key, value);
        }

        Ok(Msm::new(&bases, &scalars, &fixed_base_scalars))
    }
}

impl WriteWithFormat for Accumulator<RecursiveEmulation> {
    fn write<W: io::Write>(&self, writer: &mut W, format: SerdeFormat) -> io::Result<()> {
        self.lhs().write(writer, format)?;
        self.rhs().write(writer, format)
    }
}

impl ReadWithFormat for Accumulator<RecursiveEmulation> {
    fn read<R: io::Read>(reader: &mut R, format: SerdeFormat) -> io::Result<Self> {
        let lhs = Msm::read(reader, format)?;
        let rhs = Msm::read(reader, format)?;
        Ok(Accumulator::<RecursiveEmulation>::new(lhs, rhs))
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use group::Group;
    use proptest::prelude::*;

    use super::*;
    use crate::BaseFieldElement;

    /// Four distinct non-identity points, so a substituted or reordered base is observable.
    fn distinct_non_identity_points() -> [EmulatedCurve; 4] {
        let generator = EmulatedCurve::generator();
        let doubled = generator.double();
        [generator, doubled, doubled + generator, doubled.double()]
    }

    fn scalar_from_bytes(bytes: [u8; 32]) -> NativeField {
        BaseFieldElement::from_raw(&bytes)
            .expect("from_raw applies modulus reduction and cannot fail")
            .0
    }

    fn encode_to_bytes<T: WriteWithFormat>(value: &T) -> Vec<u8> {
        let mut bytes = Vec::new();
        value
            .write(&mut bytes, SerdeFormat::RawBytesUnchecked)
            .expect("writing to a vector cannot fail");
        bytes
    }

    prop_compose! {
        fn arb_scalar_bytes()(bytes in prop_oneof![Just([0u8; 32]), any::<[u8; 32]>()]) -> [u8; 32] {
            bytes
        }
    }

    prop_compose! {
        /// Key shapes the committed assets never carry: empty, and multi-byte UTF-8.
        fn arb_fixed_base_key()(key in prop_oneof![
            Just(String::new()),
            "[a-zA-Z0-9_-]{1,16}",
            Just("clé".to_owned()),
            Just("鍵".to_owned()),
        ]) -> String {
            key
        }
    }

    prop_compose! {
        fn arb_msm_with_pair_count(pair_count: usize)(
            point_indices in prop::collection::vec(0usize..4, pair_count),
            scalar_bytes in prop::collection::vec(arb_scalar_bytes(), pair_count),
            named_entries in prop::collection::vec(
                (arb_fixed_base_key(), arb_scalar_bytes()), 0usize..=8,
            ),
        ) -> Msm<RecursiveEmulation> {
            let points = distinct_non_identity_points();
            let bases: Vec<EmulatedCurve> =
                point_indices.iter().map(|index| points[*index]).collect();
            let scalars: Vec<NativeField> =
                scalar_bytes.into_iter().map(scalar_from_bytes).collect();
            let fixed_base_scalars: BTreeMap<String, NativeField> = named_entries
                .into_iter()
                .map(|(key, bytes)| (key, scalar_from_bytes(bytes)))
                .collect();
            Msm::new(&bases, &scalars, &fixed_base_scalars)
        }
    }

    prop_compose! {
        fn arb_msm()(pair_count in 0usize..=4)(
            msm in arb_msm_with_pair_count(pair_count),
        ) -> Msm<RecursiveEmulation> {
            msm
        }
    }

    prop_compose! {
        /// The two sides always differ in pair count, so a swapped `lhs`/`rhs` is observable.
        fn arb_accumulator()(lhs_pair_count in 0usize..=4, offset in 1usize..=4)(
            lhs in arb_msm_with_pair_count(lhs_pair_count),
            rhs in arb_msm_with_pair_count((lhs_pair_count + offset) % 5),
        ) -> Accumulator<RecursiveEmulation> {
            Accumulator::new(lhs, rhs)
        }
    }

    /// Encodes an MSM whose declared point and scalar counts disagree, with every
    /// component itself well formed so the reader reaches the constructor.
    fn encode_with_mismatched_counts(point_count: usize, scalar_count: usize) -> Vec<u8> {
        let points = distinct_non_identity_points();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(point_count as u32).to_le_bytes());
        for index in 0..point_count {
            points[index % points.len()]
                .write(&mut bytes, SerdeFormat::RawBytesUnchecked)
                .expect("writing to a vector cannot fail");
        }
        bytes.extend_from_slice(&(scalar_count as u32).to_le_bytes());
        for _ in 0..scalar_count {
            NativeField::ZERO
                .write_raw(&mut bytes)
                .expect("writing to a vector cannot fail");
        }
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes
    }

    fn assert_msm_components_match(
        decoded: &Msm<RecursiveEmulation>,
        original: &Msm<RecursiveEmulation>,
    ) -> Result<(), TestCaseError> {
        prop_assert_eq!(decoded.bases(), original.bases());
        prop_assert_eq!(decoded.scalars(), original.scalars());
        prop_assert_eq!(decoded.fixed_base_scalars(), original.fixed_base_scalars());
        Ok(())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(100))]

        #[test]
        fn msm_round_trip_preserves_every_component(original in arb_msm()) {
            let encoded = encode_to_bytes(&original);
            let mut remaining = encoded.as_slice();
            let decoded = Msm::<RecursiveEmulation>::read(
                &mut remaining, SerdeFormat::RawBytesUnchecked,
            )?;

            prop_assert!(remaining.is_empty(), "the reader must consume the whole encoding");
            assert_msm_components_match(&decoded, &original)?;
        }

        #[test]
        fn accumulator_round_trip_preserves_both_sides(original in arb_accumulator()) {
            let encoded = encode_to_bytes(&original);
            let mut remaining = encoded.as_slice();
            let decoded = Accumulator::<RecursiveEmulation>::read(
                &mut remaining, SerdeFormat::RawBytesUnchecked,
            )?;

            prop_assert!(remaining.is_empty(), "the reader must consume the whole encoding");
            assert_msm_components_match(&decoded.lhs(), &original.lhs())?;
            assert_msm_components_match(&decoded.rhs(), &original.rhs())?;
        }

        #[test]
        #[ignore = "a truncated point payload panics in the unchecked point reader instead of returning an error"]
        fn a_truncated_encoding_is_rejected(original in arb_msm()) {
            let encoded = encode_to_bytes(&original);
            for truncated_length in 0..encoded.len() {
                let mut remaining = &encoded[..truncated_length];
                prop_assert!(
                    Msm::<RecursiveEmulation>::read(
                        &mut remaining, SerdeFormat::RawBytesUnchecked,
                    ).is_err(),
                    "a strict prefix of length {truncated_length} must be rejected",
                );
            }
        }

        #[test]
        fn mismatched_point_and_scalar_counts_are_rejected(
            point_count in 0usize..=2, scalar_count in 0usize..=2,
        ) {
            prop_assume!(point_count != scalar_count);
            let encoded = encode_with_mismatched_counts(point_count, scalar_count);
            let mut remaining = encoded.as_slice();

            prop_assert!(
                Msm::<RecursiveEmulation>::read(
                    &mut remaining, SerdeFormat::RawBytesUnchecked,
                ).is_err(),
                "an encoding declaring {point_count} points and {scalar_count} scalars must be rejected",
            );
        }
    }
}
