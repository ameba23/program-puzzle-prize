use super::*;

#[test]
fn test_should_sign() {
    let encrypted_solution = {
        let mut hasher = Blake2s256::new();
        hasher.update(b"42");
        let hash = hasher.finalize();

        // Attempt to decrypt the encrypted_solution with encrypted_solution
        let cipher = ChaCha20Poly1305::new(&hash);
        let nonce_arr: [u8; 12] = [0; 12];
        let nonce = GenericArray::from_slice(&nonce_arr[..]);
        cipher
            .encrypt(
                nonce,
                b"some message, it does not matter what it is".as_ref(),
            )
            .unwrap()
    };
    let user_config = UserConfig {
        puzzle: "What is the meaning of life".to_string(),
        encrypted_solution: hex::encode(encrypted_solution),
    };
    let aux_data = AuxData {
        solution: "42".to_string(),
    };
    let signature_request = SignatureRequest {
        message: b"A message which will be signed if the answer is correct".to_vec(),
        auxilary_data: Some(serde_json::to_vec(&aux_data).unwrap()),
    };

    assert!(ProgramPuzzlePrize::evaluate(
        signature_request,
        Some(serde_json::to_vec(&user_config).unwrap()),
        None
    )
    .is_ok());
}

#[test]
fn test_should_fail() {
    let encrypted_solution = {
        let mut hasher = Blake2s256::new();
        hasher.update(b"42");
        let hash = hasher.finalize();

        // Attempt to decrypt the encrypted_solution with encrypted_solution
        let cipher = ChaCha20Poly1305::new(&hash);
        let nonce_arr: [u8; 12] = [0; 12];
        let nonce = GenericArray::from_slice(&nonce_arr[..]);
        cipher
            .encrypt(
                nonce,
                b"some message, it does not matter what it is".as_ref(),
            )
            .unwrap()
    };
    let user_config = UserConfig {
        puzzle: "What is the meaning of life".to_string(),
        encrypted_solution: hex::encode(encrypted_solution),
    };
    let aux_data = AuxData {
        solution: "23".to_string(),
    };
    let signature_request = SignatureRequest {
        message: b"A message which will be signed if the answer is correct".to_vec(),
        auxilary_data: Some(serde_json::to_vec(&aux_data).unwrap()),
    };

    assert!(ProgramPuzzlePrize::evaluate(
        signature_request,
        Some(serde_json::to_vec(&user_config).unwrap()),
        None
    )
    .is_err());
}
