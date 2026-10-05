use super::{setup_directory_for, DirectoryStore};
use rstest::rstest;

fn every_dir(store: &DirectoryStore) -> [&str; 8] {
    [
        &store.home,
        &store.nac_dir_base,
        &store.nac_dir_impersonal,
        &store.nac_dir_personal,
        &store.server_dir,
        &store.config_dir,
        &store.virtual_dir,
        &store.file_transfer_dir,
    ]
}

// The Windows installer passes `--data-dir "%USERPROFILE%\<name>"`. Every
// form of that home must give one separator between components: a doubled
// one is what a Windows user saw in the saved-file path and had to delete
// by hand before Explorer would open it.
#[rstest]
#[case(r"C:\Users\A\.citadel-agent")]
#[case(r"C:\Users\A\.citadel-agent\")]
#[case(r"C:\Users\A\.citadel-agent/")]
#[case("C:/Users/A/.citadel-agent")]
fn a_windows_home_gives_single_separators(#[case] home: &str) {
    let store = setup_directory_for(home.to_string(), '\\');
    assert_eq!(store.home, r"C:\Users\A\.citadel-agent\");
    assert_eq!(
        store.file_transfer_dir,
        r"C:\Users\A\.citadel-agent\transfers\"
    );
    assert_eq!(store.virtual_dir, r"C:\Users\A\.citadel-agent\virtual\");
    for dir in every_dir(&store) {
        assert!(!dir.contains('/'), "{dir:?} mixes separators");
        assert!(!dir.contains(r"\\"), "{dir:?} doubles a separator");
    }
}

// The composed save path of a received file: `get_file_path`'s FileTransfer
// branch formats `{file_transfer_dir}{cid}` and pushes the name onto it.
#[test]
fn a_windows_received_file_path_has_single_separators() {
    let store = setup_directory_for(r"C:\Users\A\.citadel-agent".to_string(), '\\');
    let saved = format!(r"{}{}\{}", store.file_transfer_dir, 42, "photo.png");
    assert_eq!(saved, r"C:\Users\A\.citadel-agent\transfers\42\photo.png");
}

#[rstest]
#[case("/home/a/.citadel")]
#[case("/home/a/.citadel/")]
fn a_unix_home_is_unchanged(#[case] home: &str) {
    let store = setup_directory_for(home.to_string(), '/');
    assert_eq!(store.home, "/home/a/.citadel/");
    assert_eq!(store.file_transfer_dir, "/home/a/.citadel/transfers/");
    assert_eq!(
        store.nac_dir_impersonal,
        "/home/a/.citadel/accounts/impersonal/"
    );
    for dir in every_dir(&store) {
        assert!(!dir.contains("//"), "{dir:?} doubles a separator");
    }
}

// The platform wiring, on the platform: `setup_directory` must hand the real
// separator to the pure layout. Runs on the windows-latest CI leg.
#[cfg(target_os = "windows")]
#[test]
fn the_windows_layout_has_single_separators_on_windows() {
    let store = super::setup_directory(r"C:\Users\A\.citadel-agent".to_string()).unwrap();
    assert_eq!(
        store.file_transfer_dir,
        r"C:\Users\A\.citadel-agent\transfers\"
    );
}

#[cfg(not(target_os = "windows"))]
#[test]
fn the_unix_layout_has_single_separators_off_windows() {
    let store = super::setup_directory("/home/a/.citadel".to_string()).unwrap();
    assert_eq!(store.file_transfer_dir, "/home/a/.citadel/transfers/");
}
