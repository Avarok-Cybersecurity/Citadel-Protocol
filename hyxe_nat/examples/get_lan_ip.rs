use hyxe_nat::ip_addr::get_local_ip;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn main() {
    let lan_ip = get_local_ip().unwrap();
    let lan_ip = Ipv4Addr::from_str(&lan_ip.to_string()).unwrap();
    println!("{}", &lan_ip);
    println!("Is private? {}", lan_ip.is_private());
    println!("Is link-local? {}", lan_ip.is_link_local());
}