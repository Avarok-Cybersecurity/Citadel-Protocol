use std::fmt::{Display, Formatter};
use std::process::{Output, Stdio};

pub enum FirewallProtocol {
    TCP(u16),
    UDP(u16),
}

impl FirewallProtocol {
    pub fn get_port(&self) -> u16 {
        match self {
            FirewallProtocol::TCP(port) => *port,
            FirewallProtocol::UDP(port) => *port
        }
    }
}

impl Display for FirewallProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        #[cfg(target_os = "windows")]
            {
                let val = match self {
                    FirewallProtocol::TCP(_) => "TCP",
                    FirewallProtocol::UDP(_) => "UDP"
                };

                write!(f, "{}", val)
            }
        // lowercase for IP Tables input
        #[cfg(not(target_os="windows"))]
            {
                let val = match self {
                    FirewallProtocol::TCP(_) => "tcp",
                    FirewallProtocol::UDP(_) => "udp"
                };

                write!(f, "{}", val)
            }
    }
}

pub fn open_local_firewall_port(protocol: FirewallProtocol) -> std::io::Result<Output> {
    #[cfg(not(target_os="windows"))]
        {
            linux(protocol)
        }
    #[cfg(target_os = "windows")]
        {
            windows(protocol)
        }
}

// source: https://winaero.com/blog/open-port-windows-firewall-windows-10/
#[allow(unused)]
fn windows(protocol: FirewallProtocol) -> std::io::Result<Output> {
    let port = protocol.get_port();
    let arg_name = format!("name=\"Lusna{}\"", port);
    let arg_protocol = format!("protocol={}", protocol);
    let arg_end = format!("localport={}", port);

    std::process::Command::new("netsh")
        .arg("advfirewall")
        .arg("firewall")
        .arg("add")
        .arg("rule")
        .arg(arg_name.as_str())
        .arg("dir=in")
        .arg("action=allow")
        .arg(arg_protocol.as_str())
        .arg(arg_end.as_str())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map(|res| res.wait_with_output().unwrap())
}

#[allow(unused)]
fn linux(protocol: FirewallProtocol) -> std::io::Result<Output> {
    let port = protocol.get_port();
    let protocol_arg = format!("{}", protocol);
    let port_arg = format!("{}", port);

    std::process::Command::new("iptables")
        .arg("-A")
        .arg("INPUT")
        .arg("-p")
        .arg(protocol_arg.as_str())
        .arg("--dport")
        .arg(port_arg.as_str())
        .arg("-j")
        .arg("ACCEPT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map(|res| res.wait_with_output().unwrap())
}

#[allow(unused)]
pub fn remove_firewall_rule(protocol: FirewallProtocol) -> std::io::Result<Output> {
    #[cfg(not(target_os="windows"))]
        {
            linux_remove(protocol)
        }

    #[cfg(target_os = "windows")]
        {
            windows_remove(protocol)
        }
}

#[allow(unused)]
fn windows_remove(protocol: FirewallProtocol) -> std::io::Result<Output> {
    let port = protocol.get_port();
    let arg_name = format!("name=\"Lusna{}\"", port);
    let arg_protocol = format!("protocol={}", protocol);
    let arg_end = format!("localport={}", port);

    std::process::Command::new("netsh")
        .arg("advfirewall")
        .arg("firewall")
        .arg("delete")
        .arg("rule")
        .arg(arg_name.as_str())
        .arg(arg_protocol.as_str())
        .arg(arg_end.as_str())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map(|res| res.wait_with_output().unwrap())
}

#[allow(unused)]
fn linux_remove(protocol: FirewallProtocol) -> std::io::Result<Output> {
    let port = protocol.get_port();
    let protocol_arg = format!("{}", protocol);
    let port_arg = format!("{}", port);

    std::process::Command::new("iptables")
        .arg("-D")
        .arg("INPUT")
        .arg("-p")
        .arg(protocol_arg.as_str())
        .arg("--dport")
        .arg(port_arg.as_str())
        .arg("-j")
        .arg("ACCEPT")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map(|res| res.wait_with_output().unwrap())
}

/// Will exit if the permissions are not valid
pub fn check_permissions() {
    #[cfg(target_os = "windows")]
        {
            let output = std::process::Command::new("net")
                .arg("user")
                .arg(whoami::username())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
                .wait_with_output()
                .unwrap()
                .stdout;

            let buf = unsafe { String::from_utf8_unchecked(output) };
            let line = buf.lines().filter(|line| (*line).contains("Local Group Memberships")).collect::<Vec<&str>>();
            if line.len() == 1 {
                if line[0].to_lowercase().contains("administrators") {
                    return;
                }

                eprintln!("The current user does not have admin rights. Aborting program")
            } else {
                eprintln!("Unable to check command result. Please report to the developers");
            }

            std::process::exit(-1);
        }

    #[cfg(not(target_os="windows"))]
        {
            let output = std::process::Command::new("sudo")
                .arg("-v")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
                .wait_with_output()
                .unwrap()
                .stdout;

            let buf = unsafe { String::from_utf8_unchecked(output) };
            println!("Output: {}", &buf);

            if buf.contains("password for") {
                eprintln!("Please run this program as sudo. I.e., sudo {}", std::env::args().collect::<Vec<String>>()[0].to_string());
                std::process::exit(-1);
            }

            if buf.len() == 0 {
                return;
            }

            eprintln!("The current user does not have elevated privileges");
            std::process::exit(-1);
        }
}