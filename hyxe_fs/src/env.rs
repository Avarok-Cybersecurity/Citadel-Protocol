use std::fs::create_dir_all as mkdir;
use std::sync::Mutex;
use std::net::SocketAddr;
use crate::io::FsError;

/// Home directory
pub const BASE_NAME: &'static str = ".HyxeWave";
/// The total length of each saved file's name
pub const HYXE_FILE_OBFUSCATED_LEN: usize = 50;

lazy_static! {
    /// The hyxe home-directory ~/
    pub static ref HYXE_HOME: Mutex<Option<String>> = Mutex::new(None);
    /// base for the nac dir
    pub static ref HYXE_NAC_DIR_BASE: Mutex<Option<String>> = Mutex::new(None);
    /// directory for impersonal accounts
    pub static ref HYXE_NAC_DIR_IMPERSONAL: Mutex<Option<String>> = Mutex::new(None);
    /// Directory for personal accounts
    pub static ref HYXE_NAC_DIR_PERSONAL: Mutex<Option<String>> = Mutex::new(None);
    /// For server-only files
    pub static ref HYXE_SERVER_DIR: Mutex<Option<String>> = Mutex::new(None);
    /// Configuration files for either server or client
    pub static ref HYXE_CONFIG_DIR: Mutex<Option<String>> = Mutex::new(None);
    /// Directory for the virtual file-sharing platform
    pub static ref HYXE_VIRTUAL_DIR: Mutex<Option<String>> = Mutex::new(None);
}

#[allow(unused_results)]
fn setup_directory_w_bind_addr(bind_addr: &str, home_dir: Option<String>) -> bool {
    let home = if let Some(mut home) = home_dir {
        #[cfg(not(target_os = "windows"))]
            {
                if !home.ends_with("/") {
                    home.push('/');
                }
            }
        #[cfg(target_os = "windows")]
            {
                if !home.ends_with("\\") {
                    home.push('\\');
                }
            }

        /*if std::fs::read_dir(&home).is_err() {
            return false;
        }*/
        home
    } else {
        if let Some(home) = get_home_dir(bind_addr) {
            home
        } else {
            return false;
        }
    };

    HYXE_HOME.lock().unwrap().replace(home.clone());
    HYXE_NAC_DIR_BASE.lock().unwrap().replace(append_to_path(home.clone(), "accounts/"));
    HYXE_NAC_DIR_IMPERSONAL.lock().unwrap().replace(append_to_path(home.clone(), "accounts/impersonal/"));
    HYXE_NAC_DIR_PERSONAL.lock().unwrap().replace(append_to_path(home.clone(), "accounts/personal/"));
    HYXE_SERVER_DIR.lock().unwrap().replace(append_to_path(home.clone(), "server/"));
    HYXE_CONFIG_DIR.lock().unwrap().replace(append_to_path(home.clone(), "config/"));
    HYXE_VIRTUAL_DIR.lock().unwrap().replace(append_to_path(home.clone(), "virtual/"));

    true
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

fn append_to_path(base: String, addition: &'static str) -> String {
    format_path(base + addition)
}

/// Sets up local directories that are pre-requisite to launching either client or server application
pub fn setup_directories(bind_addr: SocketAddr, home_dir: Option<String>) -> Result<(), FsError<String>> {
    if !setup_directory_w_bind_addr(check_ipv6(bind_addr).as_str(), home_dir) {
        return Err(FsError::IoError("Unable to access base directory, or invalid home dir configuration".to_string()))
    }

    let base = mkdir(HYXE_HOME.lock().unwrap().as_ref().unwrap().as_str());
    base.and(mkdir(HYXE_NAC_DIR_BASE.lock().unwrap().as_ref().unwrap().as_str()))
        .and(mkdir(HYXE_NAC_DIR_IMPERSONAL.lock().unwrap().as_ref().unwrap().as_str()))
        .and(mkdir(HYXE_NAC_DIR_PERSONAL.lock().unwrap().as_ref().unwrap().as_str()))
        .and(mkdir(HYXE_SERVER_DIR.lock().unwrap().as_ref().unwrap().as_str()))
        .and(mkdir(HYXE_CONFIG_DIR.lock().unwrap().as_ref().unwrap().as_str()))
        .and(mkdir(HYXE_VIRTUAL_DIR.lock().unwrap().as_ref().unwrap().as_str()))
        .map_err(|err| FsError::IoError(err.to_string()))
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