#[cfg(test)]
#[cfg(feature = "jwt-testing")]
mod tests {
    use std::collections::HashMap;
    use ez_pqcrypto::constructor_opts::ConstructorOpts;
    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::hyper_ratchet::constructor::{HyperRatchetConstructor, BobToAliceTransferType};

    #[allow(unused_must_use)]
    fn setup_log() {
        let _ = env_logger::try_init();
        log::trace!(target: "lusna", "TRACE enabled");
        log::trace!(target: "lusna", "INFO enabled");
        log::warn!(target: "lusna", "WARN enabled");
        log::error!(target: "lusna", "ERROR enabled");
    }

    #[tokio::test]
    async fn jwt() {
        setup_log();
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
    fn gen(cid: u64, version: u32, endpoint_bob_cid: Option<u64>, opts: ConstructorOpts) -> (HyperRatchet, HyperRatchet) {
        let mut alice = HyperRatchetConstructor::new_alice(vec![opts.clone()], cid, version, None).unwrap();
        let bob = HyperRatchetConstructor::new_bob(cid, version, vec![opts.clone()],  alice.stage0_alice()).unwrap();
        alice.stage1_alice(&BobToAliceTransferType::Default(bob.stage0_bob().unwrap())).unwrap();
        let bob = if let Some(cid) = endpoint_bob_cid { bob.finish_with_custom_cid(cid).unwrap() } else { bob.finish().unwrap() };
        (alice.finish().unwrap(), bob)
    }
}