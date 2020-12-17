#![feature(async_closure)]

#[cfg(test)]
mod tests {
    #[test]
    fn get_ipv4() {
        tokio::runtime::Runtime::new().unwrap().block_on(get())
    }

    async fn get() {
        let ipv6 = async_ip::get_ip(None).await.unwrap();
        println!("External IP: {}", ipv6);
        let internalv6 = async_ip::get_internal_ip(true).await.unwrap();
        println!("Internal IPv6: {}", internalv6);
        let internalv4 = async_ip::get_internal_ip(false).await.unwrap();
        println!("Internal IPv4: {}", internalv4);
    }
}