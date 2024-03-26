#[macro_export]
macro_rules! impl_remote {
    ($item:ty) => {
        #[$crate::async_trait]
        impl Remote for $item {
            async fn send_with_custom_ticket(
                &self,
                ticket: Ticket,
                request: NodeRequest,
            ) -> Result<(), NetworkError> {
                self.inner.send_with_custom_ticket(ticket, request).await
            }

            async fn send_callback_subscription(
                &self,
                request: NodeRequest,
            ) -> Result<
                citadel_proto::kernel::kernel_communicator::KernelStreamSubscription,
                NetworkError,
            > {
                self.inner.send_callback_subscription(request).await
            }

            fn account_manager(&self) -> &AccountManager {
                self.inner.account_manager()
            }

            fn get_next_ticket(&self) -> Ticket {
                self.inner.get_next_ticket()
            }
        }
    };
}
