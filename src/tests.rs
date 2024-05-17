use super::*;

#[test]
fn test_should_sign() {
    let signature_request = SignatureRequest {
        message: b"some_message".to_vec(),
        auxilary_data: None,
    };

    assert!(ProgramPuzzlePrize::evaluate(signature_request, None, None).is_ok());
}

#[test]
fn test_should_fail() {
    let signature_request = SignatureRequest {
        message: Vec::new(),
        auxilary_data: None,
    };

    assert!(ProgramPuzzlePrize::evaluate(signature_request, None, None).is_err());
}