use crate::misc::AccountError;
use std::fs::create_dir_all as mkdir;
use std::path::PathBuf;

/// Home directory
pub const BASE_NAME: &str = ".citadel";
/// The total length of each saved file's name
pub const HYXE_FILE_OBFUSCATED_LEN: usize = 50;

/// Correlated to important directories for the program
#[allow(missing_docs)]
pub enum BasePath {
    Home,
    NacDirBase,
    NacDirImpersonal,
    NacDirPersonal,
    ServerDir,
    ConfigDir,
    VirtualDir,
}

#[derive(Clone)]
/// Stores important information for the filesystem
pub struct DirectoryStore {
    /// The program home-directory ~/
    pub home: String,
    /// base for the nac dir
    pub nac_dir_base: String,
    /// directory for impersonal accounts
    pub nac_dir_impersonal: String,
    /// Directory for personal accounts
    pub nac_dir_personal: String,
    /// For server-only files
    pub server_dir: String,
    /// Configuration files for either server or client
    pub config_dir: String,
    /// Directory for the virtual file-sharing platform
    pub virtual_dir: String,
}

impl DirectoryStore {
    /// Creates a properly formatted path given the `base` value (the base value should come from self)
    pub fn make_path<T: AsRef<str>>(&self, base: BasePath, file: T) -> PathBuf {
        let base = match base {
            BasePath::Home => &self.home,
            BasePath::NacDirBase => &self.nac_dir_base,
            BasePath::NacDirImpersonal => &self.nac_dir_impersonal,
            BasePath::NacDirPersonal => &self.nac_dir_personal,
            BasePath::ServerDir => &self.server_dir,
            BasePath::ConfigDir => &self.config_dir,
            BasePath::VirtualDir => &self.virtual_dir,
        };

        PathBuf::from(append_to_path(base.clone(), file.as_ref()))
    }
}

#[allow(unused_results)]
fn setup_directory(mut home_dir: String) -> Result<DirectoryStore, AccountError> {
    let home = {
        {
            if !home_dir.ends_with('/') {
                home_dir.push('/');
            }
        }
        #[cfg(target_os = "windows")]
        {
            if !home_dir.ends_with("\\") {
                home_dir.push('\\');
            }
        }

        home_dir
    };

    let hyxe_server_dir = append_to_path(home.clone(), "server/");

    let dirs = DirectoryStore {
        home: home.clone(),
        nac_dir_base: append_to_path(home.clone(), "accounts/"),
        nac_dir_impersonal: append_to_path(home.clone(), "accounts/impersonal/"),
        nac_dir_personal: append_to_path(home.clone(), "accounts/personal/"),
        server_dir: hyxe_server_dir,
        config_dir: append_to_path(home.clone(), "config/"),
        virtual_dir: append_to_path(home, "virtual/"),
    };

    Ok(dirs)
}

#[cfg(not(target_os = "windows"))]
/// #
pub fn format_path(input: String) -> String {
    input.replace('\\', "/")
}

#[cfg(any(target_os = "windows"))]
/// #
pub fn format_path(input: String) -> String {
    input.replace("/", "\\")
}

fn append_to_path(base: String, addition: &str) -> String {
    format_path(base + addition)
}

/// Sets up local directories that are pre-requisite to launching either client or server application
pub fn setup_directories(home_dir: String) -> Result<DirectoryStore, AccountError> {
    let store = setup_directory(home_dir)?;
    let base = mkdir(store.home.as_str());

    base.and(mkdir(store.nac_dir_base.as_str()))
        .and(mkdir(store.nac_dir_impersonal.as_str()))
        .and(mkdir(store.nac_dir_personal.as_str()))
        .and(mkdir(store.server_dir.as_str()))
        .and(mkdir(store.config_dir.as_str()))
        .and(mkdir(store.virtual_dir.as_str()))
        .map_err(|err| AccountError::IoError(err.to_string()))?;

    Ok(store)
}
