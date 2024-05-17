//! No-op program

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use blake2::{Blake2s256, Digest};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use entropy_programs_core::{bindgen::Error, bindgen::*, export_program, prelude::*};
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

// TODO confirm this isn't an issue for audit
register_custom_getrandom!(always_fail);

/// JSON-deserializable struct that will be used to derive the program-JSON interface.
#[cfg_attr(feature = "std", derive(schemars::JsonSchema))]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct UserConfig {
    /// The puzzle to be solved, or a link to the puzzle to be solved
    puzzle: String,
    /// The ChaCha20Poly1305 encryption of some data, using the solution's Blake2s256 hash as the
    /// key
    encrypted_solution: String,
}

/// JSON representation of the auxiliary data
#[cfg_attr(feature = "std", derive(schemars::JsonSchema))]
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct AuxData {
    /// The user-provided solution
    solution: String,
}

pub struct ProgramPuzzlePrize;

impl Program for ProgramPuzzlePrize {
    fn evaluate(
        signature_request: SignatureRequest,
        raw_config: Option<Vec<u8>>,
        _oracle_data: Option<Vec<u8>>,
    ) -> Result<(), Error> {
        let encrypted_solution = {
            // Deserialize the config
            let config = serde_json::from_slice::<UserConfig>(
                raw_config
                    .ok_or(Error::Evaluation("No config provided.".to_string()))?
                    .as_slice(),
            )
            .map_err(|e| Error::Evaluation(format!("Failed to parse config: {}", e)))?;
            hex::decode(config.encrypted_solution)
                .map_err(|e| Error::Evaluation(format!("Bad program configuration {}", e)))?
        };

        // Deserialize the aux data
        let aux_data = serde_json::from_slice::<AuxData>(
            signature_request
                .auxilary_data
                .ok_or(Error::InvalidSignatureRequest(
                    "No auxilary_data provided".to_string(),
                ))?
                .as_slice(),
        )
        .map_err(|e| {
            Error::InvalidSignatureRequest(format!("Failed to parse auxilary_data: {}", e))
        })?;

        // Hash the answer
        let mut hasher = Blake2s256::new();
        hasher.update(aux_data.solution.into_bytes());
        let hash = hasher.finalize();

        // Attempt to decrypt the encrypted_solution with encrypted_solution
        let cipher = ChaCha20Poly1305::new(&hash);
        let nonce_arr: [u8; 16] = [0; 16];
        let nonce = GenericArray::from_slice(&nonce_arr[..]);
        if cipher.decrypt(&nonce, encrypted_solution.as_ref()).is_err() {
            return Err(Error::Evaluation(
                "Sorry - your solution was incorrect!".to_string(),
            ));
        }
        Ok(())
    }

    /// Since we don't use a custom hash function, we can just return `None` here.
    fn custom_hash(_data: Vec<u8>) -> Option<Vec<u8>> {
        None
    }
}

export_program!(ProgramPuzzlePrize);
