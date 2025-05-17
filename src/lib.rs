// Here we're calling a macro exported with Uniffi. This macro will
// write some functions and bind them to FFI type. These
// functions will invoke the `get_circom_wtns_fn` generated below.
mopro_ffi::app!();

use noir::{
    barretenberg::{
        prove::prove_ultra_honk,
        srs::setup_srs_from_bytecode,
        utils::get_honk_verification_key,
        verify::verify_ultra_honk,
    },
    witness::from_vec_str_to_witness_map,
};

#[uniffi::export]
pub fn prove_anon_aadhaar_simple(srs_path: String, inputs: Vec<String>) -> Vec<u8> {
    const ANON_AADHAAR_JSON: &str = include_str!("../circuits/target/anon_aadhaar.json");
    let bytecode_json: serde_json::Value = serde_json::from_str(&ANON_AADHAAR_JSON).unwrap();
    let bytecode = bytecode_json["bytecode"].as_str().unwrap();

    setup_srs_from_bytecode(bytecode, Some(&srs_path), false).unwrap();

    let witness_vec_ref_str: Vec<&str> = inputs.iter().map(|s| s.as_str()).collect();

    let initial_witness = from_vec_str_to_witness_map(witness_vec_ref_str).unwrap();

    let start = std::time::Instant::now();
    let proof = prove_ultra_honk(bytecode, initial_witness, false).unwrap();

    println!("anon_aadhaar proof generation time: {:?}", start.elapsed());

    proof
}

#[uniffi::export]
pub fn verify_anon_aadhaar_simple(srs_path: String, proof: Vec<u8>) -> bool {
    // Assuming the anon_aadhaar circuit JSON is located at this path
    const ANON_AADHAAR_JSON: &str = include_str!("../circuits/target/anon_aadhaar.json");
    let bytecode_json: serde_json::Value = serde_json::from_str(&ANON_AADHAAR_JSON).unwrap();
    let bytecode = bytecode_json["bytecode"].as_str().unwrap();

    setup_srs_from_bytecode(bytecode, Some(&srs_path), false).unwrap();

    let vk = get_honk_verification_key(bytecode, false).unwrap();

    let start = std::time::Instant::now();
    let verdict = verify_ultra_honk(proof, vk).unwrap();

    println!("anon_aadhaar proof verification time: {:?}", start.elapsed());
    println!("anon_aadhaar proof verification verdict: {}", verdict);

    verdict
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::fs;
    use toml;

    #[derive(Deserialize, Debug)]
    struct QrDataPaddedInput {
        len: String,
        storage: Vec<String>,
    }

    #[derive(Deserialize, Debug)]
    struct ProverInput {
        #[serde(rename = "qrDataPaddedLength")]
        qr_data_padded_length: String,
        #[serde(rename = "nullifierSeed")]
        nullifier_seed: String,
        #[serde(rename = "delimiterIndices")]
        delimiter_indices: Vec<String>,
        signature_limbs: Vec<String>,
        modulus_limbs: Vec<String>,
        redc_limbs: Vec<String>,
        #[serde(rename = "revealGender")]
        reveal_gender: String,
        #[serde(rename = "revealAgeAbove18")]
        reveal_age_above18: String,
        #[serde(rename = "revealPinCode")]
        reveal_pin_code: String,
        #[serde(rename = "revealState")]
        reveal_state: String,
        #[serde(rename = "signalHash")]
        signal_hash: String,
        #[serde(rename = "qrDataPadded")]
        qr_data_padded: QrDataPaddedInput,
    }

    #[test]
    fn test_prove_and_verify_anon_aadhaar_simple() {
        let srs_path = "test-vectors/noir/anon_srs.local".to_string();

        let toml_str = fs::read_to_string("circuits/Prover.toml").expect("Failed to read Prover.toml");
        let prover_input: ProverInput = toml::from_str(&toml_str).expect("Failed to parse Prover.toml");

        let mut inputs: Vec<String> = Vec::new();
        // Order as in circuits/src/main.nr
        inputs.extend(prover_input.qr_data_padded.storage.iter().cloned());
        inputs.push(prover_input.qr_data_padded.len.clone());
        inputs.push(prover_input.qr_data_padded_length.clone());
        inputs.extend(prover_input.delimiter_indices.iter().cloned());
        inputs.extend(prover_input.signature_limbs.iter().cloned());
        inputs.extend(prover_input.modulus_limbs.iter().cloned());
        inputs.extend(prover_input.redc_limbs.iter().cloned());
        inputs.push(prover_input.reveal_age_above18.clone());
        inputs.push(prover_input.reveal_gender.clone());
        inputs.push(prover_input.reveal_pin_code.clone());
        inputs.push(prover_input.reveal_state.clone());
        inputs.push(prover_input.nullifier_seed.clone());
        inputs.push(prover_input.signal_hash.clone());

        let proof = prove_anon_aadhaar_simple(srs_path.clone(), inputs);
        assert!(!proof.is_empty(), "Proof should not be empty");
        let is_valid = verify_anon_aadhaar_simple(srs_path, proof);
        assert!(is_valid, "Proof verification should succeed");
    }
}