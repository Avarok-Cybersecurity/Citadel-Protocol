#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use hyxe_crypt::prelude::PostQuantumContainer;
    use hyxe_crypt::prelude::algorithm_dictionary::{KemAlgorithm, EncryptionAlgorithm};
    use openssl::pkey::{PKey, Private};
    use hyxe_user::misc::AccountError;
    use openssl::hash::MessageDigest;
    use jwt::{PKeyWithDigest, SignWithKey};

    #[allow(unused_must_use)]
    fn setup_log() {
        std::env::set_var("RUST_LOG", "trace");
        let _ = env_logger::try_init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn jwt() {
        setup_log();
        const USER: u64 = 999;
        const API_KEY: &str = "AIzaSyDtYt9f0c7x3uL7EhALL6isXXD0q_wGBpA";
        let auth = hyxe_user::external_services::google_auth::GoogleAuth::load_from_google_services_file("/Users/nologik/googlesvc.json").await.unwrap();
        let jwt = auth.sign_new_custom_jwt_auth(USER).unwrap();
        log::info!("JWT: {}", jwt);

        let mut firebase_rtdb = firebase_rtdb::FirebaseRTDB::new_from_jwt("https://verisend-d3aec-default-rtdb.firebaseio.com/", jwt, API_KEY).await.unwrap();
        let mut map = HashMap::new();
        map.insert("cid", "777");
        map.insert("name", "A peer");

        let resp = firebase_rtdb.root().await.unwrap().child("users").child(USER.to_string()).child("peers").final_node("777").post(&map).await.unwrap();
        log::info!("RESP: {}", resp);

        firebase_rtdb.renew_token().await.unwrap();

        let resp = firebase_rtdb.root().await.unwrap().child("users").child(USER.to_string()).child("peers").child("second").final_node("777").post(&map).await.unwrap();
        log::info!("RESP: {}", resp);
    }
}