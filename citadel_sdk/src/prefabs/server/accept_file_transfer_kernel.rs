use crate::prelude::*;
use futures::StreamExt;

#[derive(Default)]
pub struct AcceptFileTransferKernel;

#[async_trait]
impl NetKernel for AcceptFileTransferKernel {
    fn load_remote(&mut self, _node_remote: NodeRemote) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_start(&self) -> Result<(), NetworkError> {
        Ok(())
    }

    async fn on_node_event_received(&self, message: NodeResult) -> Result<(), NetworkError> {
        if let NodeResult::ObjectTransferHandle(mut handle) = message {
            handle
                .handle
                .accept()
                .map_err(|err| NetworkError::Generic(err.into_string()))?;
            exhaust_file_transfer(handle.handle);
        }

        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}

pub fn exhaust_file_transfer(mut handle: ObjectTransferHandler) {
    // Exhaust the stream
    let handle = citadel_io::tokio::task::spawn(async move {
        while let Some(evt) = handle.next().await {
            log::info!(target: "citadel", "File Transfer Event: {evt:?}");
            if let ObjectTransferStatus::Fail(err) = &evt {
                log::error!(target: "citadel", "File Transfer Failed: {err:?}");
                std::process::exit(1);
            } else if let ObjectTransferStatus::TransferComplete = &evt {
                break;
            }
        }
    });

    drop(handle);
}
