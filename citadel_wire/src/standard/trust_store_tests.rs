use super::{trust_store, LoadedRoots, ReadOnce, RootSource};
use crate::exports::Certificate;
use citadel_io::{ErrorCode, NetworkError};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A root source that gives what the test says, as the OS's would.
struct Given(fn() -> LoadedRoots);

impl RootSource for Given {
    fn load(&self) -> LoadedRoots {
        (self.0)()
    }
}

fn root(byte: u8) -> Certificate<'static> {
    Certificate::from(vec![0x30, byte])
}

fn refused_code(source: Given) -> ErrorCode {
    let err = trust_store(&source).expect_err("an incomplete store was accepted");
    NetworkError::from(err).code
}

#[test]
fn a_whole_store_is_kept() {
    let store = trust_store(&Given(|| LoadedRoots {
        certs: vec![root(1), root(2)],
        errors: vec![],
    }))
    .unwrap();
    assert_eq!(store, vec![root(1), root(2)]);
}

/// The macOS failure: every trust domain refused with errSecIO.
#[test]
fn a_store_the_os_could_not_read_is_refused_by_code() {
    let code = refused_code(Given(|| LoadedRoots {
        certs: vec![],
        errors: vec!["failed to load system trust settings: I/O error. (-36)".into()],
    }));
    assert_eq!(code, ErrorCode::TrustStoreUnavailable);
}

/// One domain failing used to leave a store that silently trusted less than the system does.
#[test]
fn a_store_read_in_part_is_refused_not_used() {
    let err = trust_store(&Given(|| LoadedRoots {
        certs: vec![root(1)],
        errors: vec!["failed to load admin trust settings: I/O error. (-36)".into()],
    }))
    .expect_err("a partial store was used");
    let err = NetworkError::from(err);
    assert_eq!(err.code, ErrorCode::TrustStoreUnavailable);
    assert!(err.to_string().contains("admin trust settings"), "{err}");
}

#[test]
fn an_empty_store_is_refused() {
    let code = refused_code(Given(LoadedRoots::default));
    assert_eq!(code, ErrorCode::TrustStoreUnavailable);
}

/// A source that counts its reads and fails the first one, as the OS store did under load.
struct FailsFirst(AtomicUsize);

impl RootSource for FailsFirst {
    fn load(&self) -> LoadedRoots {
        let n = self.0.fetch_add(1, Ordering::SeqCst);
        LoadedRoots {
            certs: vec![root(1)],
            errors: if n == 0 {
                vec!["failed to load system trust settings: I/O error. (-36)".into()]
            } else {
                vec![]
            },
        }
    }
}

/// Every node in a process shares one read of the store, and the first read's error is the one
/// every node reports: a second read is not a retry.
#[test]
fn a_store_read_once_is_shared_with_its_first_error() {
    let once = ReadOnce::new(FailsFirst(AtomicUsize::new(0)));
    for _ in 0..3 {
        let err = trust_store(&once).expect_err("a later read replaced the first");
        assert_eq!(
            NetworkError::from(err).code,
            ErrorCode::TrustStoreUnavailable
        );
    }
    assert_eq!(once.source.0.load(Ordering::SeqCst), 1);
}
