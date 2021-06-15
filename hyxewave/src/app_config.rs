use hyxe_net::hdp::hdp_packet_processor::includes::SocketAddr;
use hyxe_net::re_imports::HyperNodeType;
use crate::ffi::FFIIO;
use hyxe_user::backend::BackendType;
use hyxe_net::hdp::hdp_server::UnderlyingProtocol;
use serde::Deserialize;
use crate::console_error::ConsoleError;
use std::path::Path;
use std::fs::File;
use hyxe_user::re_imports::get_default_config_dir;
use std::str::FromStr;
use crate::re_exports::PRIMARY_PORT;
use std::net::IpAddr;
use hyxe_net::hdp::misc::net::TlsListener;

/// Created when parsing the command-line. If pure server or client mode is chosen,
/// only one of the fields below will contain a value. If distributed mode is used,
/// both will contain a value
#[derive(Default)]
pub struct AppConfig {
    pub local_bind_addr: Option<SocketAddr>,
    pub pipe: Option<SocketAddr>,
    pub hypernode_type: Option<HyperNodeType>,
    pub ffi_io: Option<FFIIO>,
    pub backend_type: Option<BackendType>,
    pub is_ffi: bool,
    pub home_dir: Option<String>,
    pub underlying_protocol: Option<UnderlyingProtocol>,
    pub kernel_threads: Option<usize>,
    pub daemon_mode: bool
}

#[derive(Debug, Deserialize)]
/// Located by default in ~/.HyxeWave/settings.toml
pub struct TomlConfig {
    // idx w.r.t the "hypernodes" vec below. Can be overridden via the command line
    pub default_node: String,
    pub hypernodes: Vec<HypernodeConfig>
}

#[derive(Debug, Deserialize)]
/// Allows for multiple nodes on the same device
pub struct HypernodeConfig {
    pub alias: String,
    pub local_bind_addr: Option<String>,
    pub override_home_dir: Option<String>,
    pub tls: Option<TLSTomlConfig>,
    pub backend: Option<BackendTomlConfig>,
    pub kernel_threads: Option<usize>,
    pub daemon_mode: Option<bool>
}

#[derive(Debug, Deserialize)]
pub struct TLSTomlConfig {
    pub pkcs12_path: String,
    pub password: Option<String>,
    pub domain: Option<String>
}

#[derive(Debug, Deserialize)]
pub struct BackendTomlConfig {
    pub url: String
}

impl TomlConfig {
    pub fn load_default() -> Result<Option<Self>, ConsoleError> {
        let default_path = get_default_config_dir().ok_or(ConsoleError::Default("Unable to get dir info"))?;

        if let Ok(_) = File::open(&default_path).map_err(|err| ConsoleError::Generic(err.to_string())) {
            let cfg_src = config::File::from(Path::new(default_path.as_str()));
            let cfg = config::Config::new();
            let cfg = cfg.with_merged(cfg_src).map_err(|err| ConsoleError::Generic(err.to_string()))?;
            let ret: Self = cfg.try_into().map_err(|err| ConsoleError::Generic(err.to_string()))?;

            let must_exist = ret.default_node.as_str();

            if ret.hypernodes.iter().find(|r| r.alias.as_str() == must_exist).is_some() {
                log::info!("Using config from path: {:?}", &default_path);
                Ok(Some(ret))
            } else {
                if ret.hypernodes.is_empty() {
                    Err(ConsoleError::Default("No node configurations listed. Please consult tutorial"))
                } else {
                    Err(ConsoleError::Default("Default alias does not match any listed configurations"))
                }
            }
        } else {
            Ok(None)
        }
    }

    /// Parses self into the app-compatible config
    pub fn parse_config(&self, specific_alias: Option<&str>) -> Result<AppConfig, ConsoleError> {
        let alias = specific_alias.unwrap_or(self.default_node.as_str());

        let node = self.hypernodes.iter().find(|r| r.alias.as_str() == alias).ok_or(ConsoleError::Default("Supplied alias not found"))?;

        let (local_bind_addr, hypernode_type) = if let Some(bind_addr) = node.local_bind_addr.as_ref() {
            (SocketAddr::from_str(bind_addr.as_str()).map_err(|err| ConsoleError::Generic(err.to_string()))?, HyperNodeType::GloballyReachable)
        } else {
            (SocketAddr::new(IpAddr::from_str("127.0.0.1").unwrap(), PRIMARY_PORT), HyperNodeType::BehindResidentialNAT)
        };

        let backend_type = node.backend.as_ref().map(|r| BackendType::SQLDatabase(r.url.clone()));

        let home_dir = node.override_home_dir.clone();
        let underlying_proto = if let Some(tls) = node.tls.as_ref() {
            UnderlyingProtocol::Tls(TlsListener::load_tls_pkcs(tls.pkcs12_path.as_str(), tls.password.as_ref().map(|r| r.as_str()).unwrap_or("")).map_err(|err| ConsoleError::Generic(format!("Unable to load PKCS-12: {:?}", err)))?, tls.domain.clone())
        } else {
            UnderlyingProtocol::Tcp
        };

        let kernel_threads = node.kernel_threads.clone();
        let daemon_mode = node.daemon_mode.unwrap_or(false);

        Ok(AppConfig {
            local_bind_addr: Some(local_bind_addr),
            pipe: None,
            hypernode_type: Some(hypernode_type),
            ffi_io: None,
            backend_type,
            is_ffi: false,
            home_dir,
            underlying_protocol: Some(underlying_proto),
            kernel_threads,
            daemon_mode
        })
    }
}