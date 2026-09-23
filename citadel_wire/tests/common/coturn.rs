//! Test-only harness: runs a local coturn (`turnserver`, e.g. `brew install coturn`) on loopback
//! with long-term credentials and a freshly generated self-signed TLS certificate for
//! `localhost`. The certificate is trusted only by the TLS client config these tests build;
//! production code verifies `turns:` servers against the native root store.
#![allow(dead_code)]

use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const USER: &str = "citadel";
pub const PASSWORD: &str = "relay-test-pass";
pub const REALM: &str = "citadel.test";

pub struct Coturn {
    child: Child,
    dir: PathBuf,
    pub port: u16,
    pub tls_port: u16,
    pub cert_der: Vec<u8>,
    /// Ports coturn allocates relayed addresses from.
    pub relay_ports: std::ops::RangeInclusive<u16>,
}

fn free_port() -> u16 {
    // Both the UDP and TCP listeners bind this port; probe TCP and UDP together.
    loop {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

impl Coturn {
    /// `max_lifetime` caps allocation lifetimes, so refresh can be exercised in seconds.
    pub fn start(max_lifetime: Duration) -> Self {
        let bin = which_turnserver();
        let dir = std::env::temp_dir().join(format!("citadel-coturn-{}", uuid_like()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let (cert_path, key_path) = (dir.join("cert.pem"), dir.join("key.pem"));
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();
        let (port, tls_port) = (free_port(), free_port());
        let relay_base = 40000 + (port % 2000) * 10;
        // citadel_logging's panic hook exits the process, so Drop never runs on a failed test;
        // a shell watchdog kills turnserver once the test process is gone (or on SIGTERM).
        const WATCHDOG: &str = "p=$1; shift; \"$@\" & c=$!; trap 'kill $c; exit 0' TERM; \
            while kill -0 \"$p\" 2>/dev/null && kill -0 $c 2>/dev/null; do sleep 1; done; kill $c";
        let child = Command::new("sh")
            .args(["-c", WATCHDOG, "sh", &std::process::id().to_string()])
            .arg(bin)
            .args(["-n", "--lt-cred-mech", "--fingerprint"])
            .args(["--listening-ip", "127.0.0.1", "--relay-ip", "127.0.0.1"])
            .args(["--listening-port", &port.to_string()])
            .args(["--tls-listening-port", &tls_port.to_string()])
            .args(["--min-port", &relay_base.to_string()])
            .args(["--max-port", &(relay_base + 9).to_string()])
            .args(["--user", &format!("{USER}:{PASSWORD}"), "--realm", REALM])
            .args(["--allow-loopback-peers", "--simple-log"])
            .arg(format!(
                "--max-allocate-lifetime={}",
                max_lifetime.as_secs()
            ))
            .arg("--cert")
            .arg(&cert_path)
            .arg("--pkey")
            .arg(&key_path)
            .arg("--pidfile")
            .arg(dir.join("turnserver.pid"))
            .arg("--log-file")
            .arg(dir.join("turnserver.log"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to spawn turnserver");
        let this = Self {
            child,
            dir,
            port,
            tls_port,
            cert_der: cert.cert.der().to_vec(),
            relay_ports: relay_base..=relay_base + 9,
        };
        this.wait_listening();
        this
    }

    fn wait_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        for port in [self.port, self.tls_port] {
            let addr = SocketAddr::from(([127, 0, 0, 1], port));
            while TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_err() {
                assert!(Instant::now() < deadline, "coturn did not start listening");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    pub fn url(&self, transport: &str) -> String {
        match transport {
            "udp" => format!("turn:127.0.0.1:{}?transport=udp", self.port),
            "tcp" => format!("turn:127.0.0.1:{}?transport=tcp", self.port),
            "tls" => format!("turns:localhost:{}?transport=tcp", self.tls_port),
            other => panic!("unknown transport {other}"),
        }
    }

    /// Trusts exactly this server's self-signed certificate (test-only).
    pub fn tls_config(&self) -> Arc<rustls::ClientConfig> {
        Arc::new(citadel_wire::tls::create_rustls_client_config(&[&self.cert_der]).unwrap())
    }

    pub fn log(&self) -> String {
        std::fs::read_to_string(self.dir.join("turnserver.log")).unwrap_or_default()
    }
}

impl Drop for Coturn {
    fn drop(&mut self) {
        // SIGTERM, not SIGKILL: the watchdog's trap forwards it to turnserver.
        let _ = Command::new("kill")
            .arg(self.child.id().to_string())
            .status();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn which_turnserver() -> PathBuf {
    if let Ok(bin) = std::env::var("CITADEL_TURNSERVER_BIN") {
        return bin.into();
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|d| d.join("turnserver"))
        .find(|p| p.is_file())
        .expect("coturn's turnserver not found on PATH (brew install coturn / apt install coturn)")
}

fn uuid_like() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos() ^ rand::random::<u64>() as u128
    )
}
