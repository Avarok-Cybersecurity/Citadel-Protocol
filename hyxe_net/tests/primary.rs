#![feature(try_trait)]

#[cfg(test)]
mod tests {
    use std::error::Error;
    use hyxe_net::dapp::application::Application;
    use hyxe_net::error::NetworkError;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "info,error,warn,trace");
        env_logger::init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn main() -> Result<(), Box<dyn Error>> {
        let dapp = Application::new();
        let var0 = dapp.create_mutex_variable("Hello, world!".to_string());
        let var1 = dapp.create_rwlock_variable(0usize);
        var1.read().await.ok_or(Box::new(default_error("bad read")))?;

        Ok(())
    }

    fn default_error(msg: &'static str) -> std::io::Error {
        std::io::Error::new(std::io::ErrorKind::Other, msg)
    }
}