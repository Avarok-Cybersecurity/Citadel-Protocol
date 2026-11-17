//! The browser's security keys, with a real key: one enrolled through the browser gives the same
//! factor when it signs in, and is refused a second enrolment. It needs a FIDO2 key with a PIN and
//! someone to touch it, so it runs in an interactive browser:
//!
//! ```bash
//! cd citadel_sdk
//! wasm-pack test --chrome --release -- --no-default-features --features security-key \
//!     --test wasm_security_key
//! ```
//!
//! Open the page it prints with `localhost` in place of `127.0.0.1` (`http://localhost:8000`): the
//! relying party is `localhost`, and WebAuthn refuses one that is not the page's host. If port 8000
//! is taken, set `WASM_BINDGEN_TEST_ADDRESS=127.0.0.1:<port>`.
#![cfg(all(target_family = "wasm", feature = "security-key"))]

use citadel_io::ErrorCode;
use citadel_sdk::prelude::*;
use citadel_user::auth::pq::client::SecurityKeyAnswer;
use citadel_user::auth::pq::kem::{EncapsulationKey, FactorKeypair};
use citadel_user::auth::pq::seed::security_key_seed;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

const RP_ID: &str = "localhost";
const PRF_EVAL_SALT: [u8; 32] = [0x2a; 32];

fn request(ceremony: SecurityKeyCeremony) -> SecurityKeyRequest {
    SecurityKeyRequest {
        rp_id: RP_ID.into(),
        prf_eval_salt: PRF_EVAL_SALT,
        ceremony,
    }
}

fn register(exclude_credential_ids: Vec<Vec<u8>>) -> SecurityKeyRequest {
    request(SecurityKeyCeremony::Register {
        user_id: vec![7; 32],
        user_name: "wasm-security-key".into(),
        exclude_credential_ids,
    })
}

/// The ML-KEM factor the server would store for this answer.
fn factor(answer: &SecurityKeyAnswer) -> EncapsulationKey {
    let seed = security_key_seed(&answer.prf, &answer.credential_id);
    FactorKeypair::derive(&seed)
        .unwrap()
        .encapsulation_key()
        .clone()
}

#[wasm_bindgen_test]
async fn a_key_enrolled_in_the_browser_signs_in_with_the_same_factor_and_only_once() {
    let key = SecurityKey::new().serve();

    let enrolled = key
        .ask(SecurityKeyPurpose::Enrol, register(Vec::new()))
        .await
        .expect("enrolment");

    let credential_ids = vec![enrolled.credential_id.clone()];
    let signed_in = key
        .ask(
            SecurityKeyPurpose::SignIn,
            request(SecurityKeyCeremony::Authenticate { credential_ids }),
        )
        .await
        .expect("sign-in");
    assert_eq!(signed_in.credential_id, enrolled.credential_id);
    assert_eq!(factor(&signed_in), factor(&enrolled));

    let again = key
        .ask(
            SecurityKeyPurpose::Enrol,
            register(vec![enrolled.credential_id.clone()]),
        )
        .await
        .expect_err("the same key was enrolled twice");
    assert_eq!(again.code, ErrorCode::PqSignInSecurityKey);
    assert_eq!(
        again.into_string(),
        "This security key is already enrolled on this account."
    );
}
