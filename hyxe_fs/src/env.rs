use std::fs::create_dir_all as mkdir;
use parking_lot::RwLock;
use std::sync::Arc;
use std::net::SocketAddr;
use crate::io::FsError;
use std::path::PathBuf;

/// Home directory
pub const BASE_NAME: &str = ".lusna";
/// The total length of each saved file's name
pub const HYXE_FILE_OBFUSCATED_LEN: usize = 50;

/// A container for storing all required paths for the program
pub struct HyxeDirsInner {
    /// The hyxe home-directory ~/
    pub hyxe_home: String,
    /// base for the nac dir
    pub hyxe_nac_dir_base: String,
    /// directory for impersonal accounts
    pub hyxe_nac_dir_impersonal: String,
    /// Directory for personal accounts
    pub hyxe_nac_dir_personal: String,
    /// For server-only files
    pub hyxe_server_dir: String,
    /// Configuration files for either server or client
    pub hyxe_config_dir: String,
    /// Directory for the virtual file-sharing platform
    pub hyxe_virtual_dir: String,
    /// The default save path of the local node's NAC
    pub nac_node_default_store_location: String
}

/// Correlated to important directories for the program
#[allow(missing_docs)]
pub enum BasePath {
    Home, NacDirBase, NacDirImpersonal, NacDirPersonal, ServerDir, ConfigDir, VirtualDir
}

/// A thread-safe container
#[derive(Clone)]
pub struct DirectoryStore {
    /// Enables access to the inner elements
    pub inner: Arc<RwLock<HyxeDirsInner>>
}

impl DirectoryStore {
    /// Creates a properly formatted path given the `base` value (the base value should come from self)
    pub fn make_path<T: AsRef<str>>(&self, base: BasePath, file: T) -> PathBuf {
        let read = self.inner.read();
        let base = match base {
            BasePath::Home => &read.hyxe_home,
            BasePath::NacDirBase => &read.hyxe_nac_dir_base,
            BasePath::NacDirImpersonal => &read.hyxe_nac_dir_impersonal,
            BasePath::NacDirPersonal => &read.hyxe_nac_dir_personal,
            BasePath::ServerDir => &read.hyxe_server_dir,
            BasePath::ConfigDir => &read.hyxe_config_dir,
            BasePath::VirtualDir => &read.hyxe_virtual_dir
        };

        PathBuf::from(append_to_path(base.clone(), file.as_ref()))
    }
}

#[allow(unused_results)]
fn setup_directory_w_bind_addr(bind_addr: &str, nac_serialized_extension: &'static str, home_dir: Option<String>) -> Result<DirectoryStore, FsError<String>> {
    let home = if let Some(mut home) = home_dir {
        #[cfg(not(target_os = "windows"))]
            {
                if !home.ends_with('/') {
                    home.push('/');
                }
            }
        #[cfg(target_os = "windows")]
            {
                if !home.ends_with("\\") {
                    home.push('\\');
                }
            }

        home
    } else {
        get_home_dir(bind_addr).ok_or_else(||FsError::IoError("Unable to obtain home directory".to_string()))?
    };

    let hyxe_server_dir = append_to_path(home.clone(), "server/");

    let dirs = HyxeDirsInner {
        hyxe_home: home.clone(),
        hyxe_nac_dir_base: append_to_path(home.clone(), "accounts/"),
        hyxe_nac_dir_impersonal: append_to_path(home.clone(), "accounts/impersonal/"),
        hyxe_nac_dir_personal: append_to_path(home.clone(), "accounts/personal/"),
        hyxe_server_dir: hyxe_server_dir.clone(),
        hyxe_config_dir: append_to_path(home.clone(), "config/"),
        hyxe_virtual_dir: append_to_path(home, "virtual/"),
        nac_node_default_store_location:  hyxe_server_dir + "default_server." + nac_serialized_extension
    };



    Ok(DirectoryStore { inner: Arc::new(RwLock::new(dirs)) })
}

/// Returns the default config dir
pub fn get_default_config_dir() -> Option<String> {
    Some(format!("{}/{}/settings.toml", dirs_2::home_dir()?.to_str()?, BASE_NAME))
}

#[cfg(not(target_os="windows"))]
fn get_home_dir(bind_addr: &str) -> Option<String> {
    Some(format!("{}/{}/{}/", dirs_2::home_dir()?.to_str()?, BASE_NAME, bind_addr))
}

#[cfg(any(target_os = "windows"))]
fn get_home_dir(bind_addr: &str) -> Option<String> {
    Some(format!("{}\\{}\\{}\\", dirs_2::home_dir()?.to_str()?, BASE_NAME, bind_addr))
}

#[cfg(not(target_os="windows"))]
/// #
pub fn format_path(input: String) -> String {
    input.replace("\\", "/")
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
pub fn setup_directories(bind_addr: SocketAddr, nac_serialized_extension: &'static str, home_dir: Option<String>) -> Result<DirectoryStore, FsError<String>> {
    let store = setup_directory_w_bind_addr(check_ipv6(bind_addr).as_str(), nac_serialized_extension, home_dir)?;

    let dirs = store.inner.read();

    let base = mkdir(dirs.hyxe_home.as_str());

    base.and(mkdir(dirs.hyxe_nac_dir_base.as_str()))
        .and(mkdir(dirs.hyxe_nac_dir_impersonal.as_str()))
        .and(mkdir(dirs.hyxe_nac_dir_personal.as_str()))
        .and(mkdir(dirs.hyxe_server_dir.as_str()))
        .and(mkdir(dirs.hyxe_config_dir.as_str()))
        .and(mkdir(dirs.hyxe_virtual_dir.as_str()))
        .map_err(|err| FsError::IoError(err.to_string()))?;

    std::mem::drop(dirs);
    Ok(store)
}

fn check_ipv6(bind_addr_sck: SocketAddr) -> String {
    let port = bind_addr_sck.port();
    let bind_addr = bind_addr_sck.ip().to_string();
    if bind_addr_sck.is_ipv6() {
        format!("{}_{}", bind_addr.replace("::", "ipv6"), port)
    } else {
        format!("{}_{}", bind_addr, port)
    }
}