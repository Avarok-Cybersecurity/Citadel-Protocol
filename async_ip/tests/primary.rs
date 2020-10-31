#![feature(async_closure)]

#[cfg(test)]
mod tests {
    #[test]
    fn get_ipv4() {
        tokio::runtime::Runtime::new().unwrap().block_on(get())
    }

    async fn get() {
        println!("Getting IP...");
        let ip = async_ip::get_ip(true, None).await.unwrap();
        println!("IP: {}", ip);
    }
}