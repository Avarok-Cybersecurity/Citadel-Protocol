#[cfg(test)]
mod tests {
    use hyxewave::ffi::{KernelResponse, DomainResponse};
    use hyxe_user::fcm::data_structures::FcmTicket;

    #[test]
    fn misc() {
        let fcm_ticket = FcmTicket::new(123, 456, 789);
        let message = Vec::from("Hello, world!");
        let resp = KernelResponse::DomainSpecificResponse(DomainResponse::FcmMessage(hyxewave::ffi::FcmMessage{ fcm_ticket, message }));
        println!("{}", serde_json::to_string(&resp).unwrap());
    }

}