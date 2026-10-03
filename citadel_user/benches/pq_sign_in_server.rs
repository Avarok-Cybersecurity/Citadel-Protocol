//! What a post-quantum login costs the server: the OPRF evaluation, one ML-KEM-1024
//! encapsulation per challenged factor, and the tag check. Nothing here stretches a password.
//!
//! `cargo bench -p citadel_user --bench pq_sign_in_server`

use citadel_io::tokio;
use citadel_types::crypto::SecBuffer;
use citadel_user::auth::pq::client::{ClientLogin, ClientProof, ClientRegistration};
use citadel_user::auth::pq::kem::encapsulate;
use citadel_user::auth::pq::login_transcript;
use citadel_user::auth::pq::messages::LoginProof;
use citadel_user::auth::pq::oprf::{client_blind, server_evaluate, OprfSeed};
use citadel_user::auth::pq::record::{KsfParams, PqAuthRecord};
use citadel_user::auth::pq::server::{
    build_login_challenge, registration_reply, AccountAuth, Expectation, PqAuthServerSettings,
};
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};

fn settings() -> PqAuthServerSettings {
    PqAuthServerSettings::new(OprfSeed::from_bytes([1u8; 32]), KsfParams::FLOOR).unwrap()
}

fn record(runtime: &tokio::runtime::Runtime) -> PqAuthRecord {
    let password = SecBuffer::from(b"bench password".to_vec());
    let (start, client) = ClientRegistration::start("bench", &password).unwrap();
    let (reply, pending) = registration_reply(&settings(), &start).unwrap();
    let (finish, _) = runtime.block_on(client.finish(&reply, false)).unwrap();
    pending.finish(finish, 0).unwrap()
}

fn server_cost(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let settings = settings();
    let record = record(&runtime);
    let password = SecBuffer::from(b"bench password".to_vec());
    let (_, blinded) = client_blind(&[7u8; 32]).unwrap();
    let ek = record.factor(1).unwrap().ek.clone();

    c.bench_function("oprf_evaluate (ristretto255)", |b| {
        b.iter(|| server_evaluate(settings.oprf_seed(), "bench", &blinded).unwrap())
    });
    c.bench_function("ml_kem_1024_encapsulate", |b| {
        b.iter(|| encapsulate(&ek).unwrap())
    });
    c.bench_function("login_challenge (oprf + 1 encapsulation)", |b| {
        b.iter_batched(
            || {
                ClientLogin::start("bench", Some(&password), None)
                    .unwrap()
                    .0
            },
            |start| build_login_challenge(&settings, AccountAuth::PostQuantum(&record), &start),
            BatchSize::SmallInput,
        )
    });
    c.bench_function("login_verify (tag check + session key)", |b| {
        b.iter_batched(
            || {
                let (start, client) = ClientLogin::start("bench", Some(&password), None).unwrap();
                let account = AccountAuth::PostQuantum(&record);
                let (challenge, expectation) =
                    build_login_challenge(&settings, account, &start).unwrap();
                let transcript = login_transcript(1, &start, &challenge);
                let proof = runtime
                    .block_on(client.respond(&challenge, &transcript, None))
                    .unwrap();
                let (Expectation::Factors(expected), ClientProof::Factors { proof, .. }) =
                    (expectation, proof)
                else {
                    unreachable!()
                };
                let LoginProof::Factors(finish) = proof else {
                    unreachable!()
                };
                (expected.bind(transcript), finish)
            },
            |(pending, finish)| pending.verify(&finish).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, server_cost);
criterion_main!(benches);
