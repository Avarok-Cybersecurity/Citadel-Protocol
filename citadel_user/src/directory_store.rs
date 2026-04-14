//! # Directory Store Management
//!
//! This module manages the filesystem structure for the Citadel Protocol,
//! handling directory creation, path management, and file organization for
//! both client and server applications.
//!
//! ## Features
//!
//! * **Directory Structure**
//!   - Home directory management (.citadel)
//!   - Account storage organization
//!   - Server and client configuration
//!   - Virtual filesystem support
//!
//! * **Path Management**
//!   - Cross-platform path handling
//!   - Standardized path formatting
//!   - Directory hierarchy maintenance
//!   - File path generation
//!
//! * **Storage Organization**
//!   - Personal account storage
//!   - Impersonal account storage
//!   - File transfer management
//!   - Configuration storage
//!
//! ## Directory Structure
//!
//! ```text
//! .citadel/
//! ├── accounts/
//! │   ├── personal/     # Personal account storage
//! │   └── impersonal/   # Impersonal account storage
//! ├── server/           # Server-specific files
//! ├── config/           # Configuration files
//! ├── virtual/          # Virtual encrypted filesystem
//! └── transfers/        # File transfer storage
//! ```
//!
//! ## Usage Example
//!
//! ```rust, no_run
//! use citadel_user::directory_store::{DirectoryStore, BasePath, setup_directories};
//! use citadel_user::backend::std_file_io::StdFileIO;
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Initialize directory structure
//! let file_io = StdFileIO;
//! let store = setup_directories(String::from("/home/user"), &file_io).await?;
//!
//! // Generate paths for different purposes
//! let config_path: PathBuf = store.make_path(
//!     BasePath::ConfigDir,
//!     "settings.conf"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Important Notes
//!
//! * All paths are automatically formatted for the target OS
//! * Directory structure is created on initialization
//! * File names in storage are obfuscated (50 chars)
//! * Base directory is `.citadel` in the user's home
//! * Paths are managed through the `BasePath` enum
//!
//! ## Related Components
//!
//! * `AccountManager` - Uses directory store for account storage
//! * `ClientNetworkAccount` - Stored in account directories
//! * `FileIOBackend` - Interacts with directory structure
//! * `VirtualFilesystem` - Uses virtual directory
//!

use crate::backend::file_io::FileIO;
use crate::misc::{format_path, AccountError};
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
    FileTransferDir,
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
    /// Directory for the virtual encrypted filesystem
    pub virtual_dir: String,
    /// Directory for basic file transfer
    pub file_transfer_dir: String,
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
            BasePath::FileTransferDir => &self.file_transfer_dir,
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
        virtual_dir: append_to_path(home.clone(), "virtual/"),
        file_transfer_dir: append_to_path(home, "transfers/"),
    };

    Ok(dirs)
}

fn append_to_path(base: String, addition: &str) -> String {
    format_path(base + addition)
}

/// Sets up local directories that are pre-requisite to launching either client or server application.
///
/// Uses the provided [`FileIO`] implementation to create directories asynchronously,
/// supporting both standard filesystem and OPFS backends.
pub async fn setup_directories(
    home_dir: String,
    file_io: &dyn FileIO,
) -> Result<DirectoryStore, AccountError> {
    let store = setup_directory(home_dir)?;

    let dirs = [
        store.home.as_str(),
        store.nac_dir_base.as_str(),
        store.nac_dir_impersonal.as_str(),
        store.nac_dir_personal.as_str(),
        store.server_dir.as_str(),
        store.config_dir.as_str(),
        store.virtual_dir.as_str(),
        store.file_transfer_dir.as_str(),
    ];

    for dir in dirs {
        file_io.create_dir_all(dir).await?;
    }

    Ok(store)
}
