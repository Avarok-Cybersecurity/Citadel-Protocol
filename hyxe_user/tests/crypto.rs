#[cfg(test)]
#[cfg(feature = "jwt-testing")]
mod tests {
    use std::collections::HashMap;
    use ez_pqcrypto::constructor_opts::ConstructorOpts;
    use hyxe_crypt::stacked_ratchet::StackedRatchet;
    use hyxe_crypt::stacked_ratchet::constructor::{StackedRatchetConstructor, BobToAliceTransferType};

    #[tokio::test]
    async fn jwt() {
        lusna_logging::setup_log();
        const USER: u64 = 999;
        const API_KEY: &str = "AIzaSyDtYt9f0c7x3uL7EhALL6isXXD0q_wGBpA";
        let auth = hyxe_user::external_services::google_auth::GoogleAuth::load_from_google_services_file("/Users/nologik/googlesvc.json").await.unwrap();
        let jwt = auth.sign_new_custom_jwt_auth(USER).unwrap();
        log::trace!(target: "lusna", "JWT: {}", jwt);

        let mut firebase_rtdb = firebase_rtdb::FirebaseRTDB::new_from_jwt("https://verisend-d3aec-default-rtdb.firebaseio.com/", jwt, API_KEY).await.unwrap();
        let mut map = HashMap::new();
        map.insert("cid", "777");
        map.insert("name", "A peer");

        let resp = firebase_rtdb.root().await.unwrap().child("users").child(USER.to_string()).child("peers").final_node("777").post(&map).await.unwrap();
        log::trace!(target: "lusna", "RESP: {}", resp);

        firebase_rtdb.renew_token().await.unwrap();

        let resp = firebase_rtdb.root().await.unwrap().child("users").child(USER.to_string()).child("peers").child("second").final_node("777").post(&map).await.unwrap();
        log::trace!(target: "lusna", "RESP: {}", resp);
    }

    #[allow(dead_code)]
    fn gen(cid: u64, version: u32, endpoint_bob_cid: Option<u64>, opts: ConstructorOpts) -> (StackedRatchet, StackedRatchet) {
        let mut alice = StackedRatchetConstructor::new_alice(vec![opts.clone()], cid, version, None).unwrap();
        let bob = StackedRatchetConstructor::new_bob(cid, version, vec![opts.clone()],  alice.stage0_alice()).unwrap();
        alice.stage1_alice(&BobToAliceTransferType::Default(bob.stage0_bob().unwrap())).unwrap();
        let bob = if let Some(cid) = endpoint_bob_cid { bob.finish_with_custom_cid(cid).unwrap() } else { bob.finish().unwrap() };
        (alice.finish().unwrap(), bob)
    }
}