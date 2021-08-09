#[cfg(test)]
mod tests {
    use std::error::Error;
    use satori_nos::application::{Application, NetworkUpdateState};

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
        let app = Application::new();
        let var0 = app.create_mutex_variable(String::from("Heya!"));
        let vid = var0.vid();

        tokio::task::spawn(async move {
            //let res = app.update(NetworkUpdateState::ValueModified { vid, value: bincode2::serialize(&String::from("Hello to the world!")).unwrap() }).await;
            let res1 = app.update(NetworkUpdateState::AllowWrite { vid }).await;
            log::info!("Res: {:?} ... {:?}", 2, res1);
        });

        let mut guard = var0.write().await.unwrap();
        guard.push('c');
        log::info!("Val now: {:?}", &*guard);
        std::mem::drop(guard);

        Ok(())
    }
}