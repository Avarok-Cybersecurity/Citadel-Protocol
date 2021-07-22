#![feature(async_closure)]

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn get() {
        let ipv6 = async_ip::get_ip(None, false).await.unwrap();
        println!("External IPv4: {}", ipv6);
        let ipv6 = async_ip::get_ip(None, true).await.unwrap();
        println!("External IPv6: {}", ipv6);
        let internalv6 = async_ip::get_internal_ip(true).await.unwrap();
        println!("Internal IPv6: {}", internalv6);
        let internalv4 = async_ip::get_internal_ip(false).await.unwrap();
        println!("Internal IPv4: {}", internalv4);
    }
}