use crate::app_config::AppConfig;
use hyxe_user::account_manager::AccountManager;
use hyxe_net::kernel::kernel_executor::KernelExecutor;
use crate::kernel::CLIKernel;
use hyxe_net::error::NetworkError;
use tokio::runtime::Runtime;
use std::sync::Arc;

/// This function will BLOCK the calling thread until the runtime is done executing
pub fn execute(config: AppConfig) -> Result<(), NetworkError> {
    // CLAP will ensure this value always have Some
    let bind_addr = config.local_bind_addr.clone().unwrap();
    let hypernode_type = config.hypernode_type.unwrap();
    let server_aux_cfg = config.aux_options.clone();
    let rt = Arc::new(build_rt(config.kernel_threads)?);
    let rt_ke = rt.clone();
    rt.block_on(async move {
        let account_manager = get_account_manager(&config).await?;
        let kernel = CLIKernel::new(config, account_manager.clone()).await;
        match KernelExecutor::new(rt_ke, hypernode_type, account_manager, kernel, bind_addr, server_aux_cfg).await {
            Ok(server) => {
                server.execute().await
            },

            Err(err) => {
                colour::red_ln!("Unable to start HDP Server: {}", err.to_string());
                Err(err)
            }
        }
    })
}

async fn get_account_manager(app_config: &AppConfig) -> Result<AccountManager, NetworkError> {
    AccountManager::new(app_config.local_bind_addr.clone().unwrap(), app_config.home_dir.clone())
        .await
        .map_err(|err| NetworkError::Generic(err.to_string()))
}

fn build_rt(core_threads: Option<usize>) -> Result<Runtime, NetworkError> {
    if let Some(core_threads) = core_threads {
        if core_threads > 1 {
            tokio::runtime::Builder::new_multi_thread()
                .enable_io()
                .enable_time()
                .worker_threads(core_threads)
                .build()
                .map_err(|err| NetworkError::Generic(err.to_string()))
        } else {
            tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .map_err(|err| NetworkError::Generic(err.to_string()))
        }
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(|err| NetworkError::Generic(err.to_string()))
    }
}