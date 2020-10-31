use crate::app_config::AppConfig;
use hyxe_user::account_manager::AccountManager;
use hyxe_net::constants::PRIMARY_PORT;
use hyxe_net::kernel::kernel_executor::KernelExecutor;
use crate::kernel::CLIKernel;
use hyxe_net::error::NetworkError;

pub async fn execute(config: AppConfig, acc_manager: AccountManager) -> Result<(), NetworkError> {
    // CLAP will ensure this value always have Some
    let bind_addr = config.bind_addr.clone().unwrap();
    let hypernode_type = config.hypernode_type.unwrap();
    let kernel = CLIKernel::new(config, acc_manager.clone()).await;
    match KernelExecutor::new(hypernode_type,acc_manager, kernel, bind_addr.to_string(),PRIMARY_PORT).await {
        Ok(server) => {
            server.execute().await
        },

        Err(err) => {
            colour::red_ln!("Unable to start HDP Server: {}", err.to_string());
            Err(err)
        }
    }
}