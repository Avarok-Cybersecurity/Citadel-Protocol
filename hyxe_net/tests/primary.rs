#![feature(async_closure)]

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rand::RngCore;
    use secstr::SecVec;

    use hyxe_net::kernel::kernel::DummyKernel;
    use hyxe_net::kernel::kernel_executor::KernelExecutor;
    use hyxe_net::constants::{MULTIPORT_END, MULTIPORT_START, PRIMARY_PORT};
    use hyxe_net::proposed_credentials::ProposedCredentials;
    use hyxe_user::account_manager::AccountManager;
    use tokio_util::codec::{Encoder, Decoder};
    use bytes::{Bytes, BytesMut};

    #[test]
    fn test_base64() {
        setup_log();
        let data_initial = b"Hello, world! How are y'all?";
        let mut output = BytesMut::with_capacity(u16::max_value() as usize);
        let mut codec= hyxe_net::hdp::codec::BytesCodec::new(u16::max_value() as usize);
        codec.encode(Bytes::copy_from_slice(data_initial), &mut output).unwrap();
        let mut encoded = output.split_to(output.len());
        let data = String::from_utf8(encoded.clone().freeze().to_vec()).unwrap();

        log::info!("Base 64: {}", data);

        let output = codec.decode(&mut encoded).unwrap().unwrap();
        let output = String::from_utf8(output.to_vec()).unwrap();
        assert_eq!(output.as_str(), data_initial);
        log::info!("{}", output);
    }

    fn setup_log() {
        std::env::set_var("RUST_LOG", "info,error,warn,trace");
        env_logger::init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }


    async fn setup_hdp() -> std::io::Result<()> {
        let account_manager = AccountManager::new().await.unwrap();
        let args = std::env::args().collect::<Vec<String>>();
        let mut right_arg = None;
        for arg in args.iter() {
            if arg.contains("--bind=") {
                let bind_addr = arg.split("--bind=").collect::<Vec<&str>>()[1];
                log::info!("detected custom bind address {}", &bind_addr);
                right_arg = Some(bind_addr.to_string());
                break;
            }
        }

        let bind_addr = right_arg.unwrap_or(String::from("127.0.0.1"));
        log::info!("Using bind addr: {}", &bind_addr);

        let full_name = "Thomas Braun";
        let username = format!("nologik{}", rand::prelude::ThreadRng::default().next_u64());
        //let username = "nologik14320081309009392142";
        let password = "mrmoney10";
        let password = SecVec::new(password.as_bytes().to_vec());

        let proposed_credentials = ProposedCredentials::new_unchecked(full_name, username, password);
        let do_register_first = true;
        let kernel = DummyKernel(None, bind_addr.clone(), Some(proposed_credentials), do_register_first);

        let kernel_executor = KernelExecutor::new(account_manager, kernel, bind_addr, MULTIPORT_START, MULTIPORT_END, PRIMARY_PORT).await.unwrap();
        println!("Loaded account manager");
        kernel_executor.execute().await.unwrap();
        println!("done running server!");
        Ok(())
    }

    #[tokio::test(core_threads = 4)]
    async fn server() -> std::io::Result<()> {
        setup_log();
        setup_hdp().await
    }

    #[test]
    fn client() -> Result<(), Box<dyn Error>> {
        Ok(())
    }
}