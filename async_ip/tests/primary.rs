#![feature(async_closure)]

#[cfg(test)]
mod tests {
    #[test]
    fn get_ipv4() {
        tokio::runtime::Runtime::new().unwrap().block_on(get())
    }

    async fn get() {
        let ipv6 = async_ip::get_ip(true, None).await.unwrap();
        println!("External IPv6: {}", ipv6);
        let ipv4 = async_ip::get_ip(false, None).await.unwrap();
        println!("External IPv4: {}", ipv4);
        let internalv6 = async_ip::get_internal_ip(true).await.unwrap();
        println!("Internal IPv6: {}", internalv6);
        let internalv4 = async_ip::get_internal_ip(false).await.unwrap();
        println!("Internal IPv4: {}", internalv4);
    }
}