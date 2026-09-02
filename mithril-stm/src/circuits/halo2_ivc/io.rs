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
