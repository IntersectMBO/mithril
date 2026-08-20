use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter};

use midnight_curves::Bls12;
use midnight_proofs::{poly::kzg::params::ParamsKZG, utils::SerdeFormat};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use tempfile::NamedTempFile;

use crate::circuits::trusted_setup::UNSAFE_SRS_SEED;

pub(crate) fn generate_params(k: u32, path: &str, format: SerdeFormat) -> ParamsKZG<Bls12> {
    let parent = std::path::Path::new(path).parent().expect("No parent directory.");
    let params: ParamsKZG<Bls12> =
        ParamsKZG::unsafe_setup(k, ChaCha20Rng::seed_from_u64(UNSAFE_SRS_SEED));
    fs::create_dir_all(parent).expect("Failed to create the directories.");
    // Uses the name of the higher level test calling the function to create a temporary file
    // storing the srs and renames the file once it is done being written
    // The rename at the end is atomic on most config so it should be possible to access the file
    // during the renaming when several tests create the same file
    let mut tmp_path =
        NamedTempFile::new_in(parent).expect("Failed to generate temporary file to store the SRS");
    {
        let mut writer = BufWriter::new(tmp_path.as_file_mut());
        params
            .write_custom(&mut writer, format)
            .expect("Failed to write the SRS in the temporary file.");
    }
    // Rename the temporary file holding the srs to the actual file
    tmp_path
        .persist(path)
        .expect("Failed to atomically rename SRS temp file.");

    params
}

pub(crate) fn load_params(path: &str, format: SerdeFormat) -> ParamsKZG<Bls12> {
    let file = File::open(path).expect("Failed to open the SRS file.");
    let mut reader = BufReader::new(file);
    ParamsKZG::read_custom(&mut reader, format)
        .expect("Failure while reading the SRS file during tests!")
}
