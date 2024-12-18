use crate::prelude::*;

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
            let _ = handle
                .handle
                .exhaust_stream()
                .await
                .map_err(|err| NetworkError::Generic(err.into_string()))?;
        }

        Ok(())
    }

    async fn on_stop(&mut self) -> Result<(), NetworkError> {
        Ok(())
    }
}
