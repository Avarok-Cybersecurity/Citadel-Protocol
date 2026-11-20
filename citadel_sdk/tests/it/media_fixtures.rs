//! The media fixtures and the download-and-cache mechanism that provides them.
//!
//! The suite reads fixtures from disk only. CI fetches them first, in a step of its own, by
//! running the two network tests here (`--run-ignored only`), and then runs the suite with
//! `CITADEL_OFFLINE=1`. Before, the first media test to run did the download: on #389 run
//! 44263624976 both `p2p_audio_stream` cases failed on a DNS lookup before any media code ran.
#![cfg(not(target_family = "wasm"))]

#[cfg(all(test, feature = "localhost-testing"))]
mod tests {
    use crate::common::fixtures::{
        ensure, fixture_dir, Fixture, FixtureError, FIXTURE_DIR_ENV, OFFLINE_ENV,
    };

    /// Fills the cache the suite reads (`fixture_dir()`), verifying each fixture's sha256. A
    /// network failure fails this step, loudly, instead of a media test.
    #[test]
    #[ignore = "network: CI runs it on its own before the suite"]
    fn fetch_media_fixtures() {
        for fixture in Fixture::ALL {
            let path = ensure(fixture).unwrap_or_else(|err| {
                panic!("fetching {fixture:?} into {:?}: {err}", fixture_dir())
            });
            assert!(
                path.is_some(),
                "{fixture:?} was not fetched: unset {OFFLINE_ENV} for this step"
            );
        }
    }

    struct EnvGuard(&'static str);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.0);
        }
    }

    #[test]
    fn fixture_sha256_mismatch_is_an_error_not_a_redownload() {
        let dir =
            std::env::temp_dir().join(format!("citadel_fixture_mismatch_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join(Fixture::Wav.file_name()),
            b"definitely not the wav",
        )
        .unwrap();
        let _guard = EnvGuard(FIXTURE_DIR_ENV);
        std::env::set_var(FIXTURE_DIR_ENV, &dir);
        let err = ensure(Fixture::Wav).unwrap_err();
        assert!(
            matches!(
                err,
                FixtureError::Sha256Mismatch {
                    fixture: Fixture::Wav,
                    ..
                }
            ),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Several nextest processes (or `cargo test` threads) may find the cache cold at once. Each
    /// must come back with the verified fixture: none may fail because another one's download
    /// replaced, removed or renamed the file it was writing.
    #[test]
    #[ignore = "network: run by CI's fixture step (see fetch_media_fixtures), not by the suite"]
    fn concurrent_cold_cache_fetches_all_return_the_verified_fixture() {
        const FETCHERS: usize = 8;
        let dir = std::env::temp_dir().join(format!("citadel_fixture_race_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let _guard = EnvGuard(FIXTURE_DIR_ENV);
        std::env::set_var(FIXTURE_DIR_ENV, &dir);
        let start = std::sync::Arc::new(std::sync::Barrier::new(FETCHERS));
        let fetchers: Vec<_> = (0..FETCHERS)
            .map(|_| {
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    ensure(Fixture::Vp8Ivf).map_err(|err| err.to_string())
                })
            })
            .collect();
        let failures: Vec<String> = fetchers
            .into_iter()
            .filter_map(|fetcher| match fetcher.join().unwrap() {
                Ok(Some(_)) => None,
                Ok(None) => Some("offline despite a cold cache".to_string()),
                Err(err) => Some(err),
            })
            .collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            failures.is_empty(),
            "concurrent fetches failed: {failures:?}"
        );
    }

    #[test]
    fn fixture_offline_and_absent_returns_none() {
        let dir =
            std::env::temp_dir().join(format!("citadel_fixture_offline_{}", std::process::id()));
        let _guard = EnvGuard(FIXTURE_DIR_ENV);
        let _offline = EnvGuard(OFFLINE_ENV);
        std::env::set_var(FIXTURE_DIR_ENV, &dir);
        std::env::set_var(OFFLINE_ENV, "1");
        assert!(ensure(Fixture::Vp8Ivf).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
