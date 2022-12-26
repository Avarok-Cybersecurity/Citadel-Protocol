#[cfg(test)]
#[cfg(feature = "jwt-testing")]
mod tests {
    use citadel_crypt::stacked_ratchet::constructor::{
        BobToAliceTransferType, StackedRatchetConstructor,
    };
    use citadel_crypt::stacked_ratchet::StackedRatchet;
    use citadel_pqcrypto::constructor_opts::ConstructorOpts;
    use std::collections::HashMap;

    #[tokio::test]
    async fn jwt() {
        citadel_logging::setup_log();
        const USER: u64 = 999;
        const API_KEY: &str = "AIzaSyDtYt9f0c7x3uL7EhALL6isXXD0q_wGBpA";
        let auth =
            citadel_user::external_services::google_auth::GoogleAuth::load_from_google_services_file(
                "/Users/nologik/googlesvc.json",
            )
            .await
            .unwrap();
        let jwt = auth.sign_new_custom_jwt_auth(USER).unwrap();
        log::trace!(target: "citadel", "JWT: {}", jwt);

        let mut firebase_rtdb = firebase_rtdb::FirebaseRTDB::new_from_jwt(
            "https://verisend-d3aec-default-rtdb.firebaseio.com/",
            jwt,
            API_KEY,
        )
        .await
        .unwrap();
        let mut map = HashMap::new();
        map.insert("cid", "777");
        map.insert("name", "A peer");

        let resp = firebase_rtdb
            .root()
            .await
            .unwrap()
            .child("users")
            .child(USER.to_string())
            .child("peers")
            .final_node("777")
            .post(&map)
            .await
            .unwrap();
        log::trace!(target: "citadel", "RESP: {}", resp);

        firebase_rtdb.renew_token().await.unwrap();

        let resp = firebase_rtdb
            .root()
            .await
            .unwrap()
            .child("users")
            .child(USER.to_string())
            .child("peers")
            .child("second")
            .final_node("777")
            .post(&map)
            .await
            .unwrap();
        log::trace!(target: "citadel", "RESP: {}", resp);
    }
}
