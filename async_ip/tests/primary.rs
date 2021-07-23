#![feature(async_closure)]

#[cfg(test)]
mod tests {
    use async_ip::get_all;

    #[tokio::test]
    async fn get() {
        let addrs = get_all(None).await.unwrap();
        println!("Addrs: {:?}", addrs);
    }
}