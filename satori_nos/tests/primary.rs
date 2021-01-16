#[cfg(test)]
mod tests {
    use std::error::Error;
    use satori_nos::application::Application;
    use serde::Deserialize;

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
        setup_log();
        let val = des::<&str>(&bincode2::serialize("Hello, world!").unwrap());
        let app = Application::new();
        let var0 = app.create_mutex_variable(String::from("Heya!"));
        var0.write().await.unwrap().push('c');
        Ok(())
    }

    fn des<'a, T: Deserialize<'a>>(input: &'a [u8]) -> T {
        bincode2::deserialize(input).unwrap()
    }
}