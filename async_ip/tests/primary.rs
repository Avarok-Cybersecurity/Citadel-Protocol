#[cfg(test)]
mod tests {
    use async_ip::{get_all, get_all_multi_concurrent};

    #[tokio::test]
    async fn get() {
        let addrs = get_all(None).await.unwrap();
        println!("Addrs: {:?}", addrs);
    }

    #[tokio::test]
    async fn get_multi() {
        let addrs = get_all_multi_concurrent(None).await.unwrap();
        println!("Addrs: {:?}", addrs);
    }
}