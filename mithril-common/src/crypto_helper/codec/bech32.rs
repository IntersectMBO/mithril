use anyhow::Context;
use bech32::{self, Bech32, Hrp};

use crate::StdResult;

/// Encode to bech32 given Human Readable Part (hrp) and data
pub fn encode_bech32(human_readable_part: &str, data: &[u8]) -> StdResult<String> {
    let human_readable_part = Hrp::parse(human_readable_part)
        .with_context(|| format!("Failed to parse HRP: '{human_readable_part}'"))?;
    bech32::encode::<Bech32>(human_readable_part, data)
        .with_context(|| format!("Failed to encode HRP to bech32: '{human_readable_part}'"))
}

/// Decode a bech32 string into its Human Readable Part (hrp) and data
pub fn decode_bech32(bech32_string: &str) -> StdResult<(String, Vec<u8>)> {
    let (human_readable_part, data) = bech32::decode(bech32_string)
        .with_context(|| format!("Failed to decode bech32: {bech32_string:?}"))?;
    Ok((human_readable_part.to_string(), data))
}

#[cfg(test)]
mod tests {
    use hex::FromHex;

    use super::{decode_bech32, encode_bech32};

    #[test]
    fn test_bech32_encode() {
        let hrp = "pool";
        let data =
            Vec::from_hex("edfa208d441511f9595ba80e8f3a7b07b6a80cbc9dda9d8e9d1dc039").unwrap();
        let encoded_data = encode_bech32(hrp, &data).unwrap();
        let expected_encoded_data =
            "pool1ahazpr2yz5gljk2m4q8g7wnmq7m2sr9unhdfmr5arhqrjnntwdz".to_string();

        assert_eq!(expected_encoded_data, encoded_data);
    }

    #[test]
    fn decode_bech32_returns_the_encoded_human_readable_part_and_data() {
        let hrp = "pool";
        let data =
            Vec::from_hex("edfa208d441511f9595ba80e8f3a7b07b6a80cbc9dda9d8e9d1dc039").unwrap();
        let encoded = encode_bech32(hrp, &data).unwrap();

        let (decoded_hrp, decoded_data) = decode_bech32(&encoded).unwrap();

        assert_eq!(hrp, decoded_hrp);
        assert_eq!(data, decoded_data);
    }

    #[test]
    fn decode_bech32_fails_on_an_invalid_string() {
        decode_bech32("not-bech32").expect_err("decoding an invalid string should fail");
    }
}
