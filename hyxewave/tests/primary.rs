#[cfg(test)]
mod tests {
    use hyxewave::ffi::{KernelResponse, DomainResponse};
    use hyxe_user::fcm::data_structures::FcmTicket;

    #[test]
    fn misc() {
        let fcm_ticket = FcmTicket::new(123, 456, 789);
        let message = Vec::from("Hello, world!");
        let resp = KernelResponse::DomainSpecificResponse(DomainResponse::FcmMessage(hyxewave::ffi::FcmMessage{ fcm_ticket, message }));
        let resp2 = KernelResponse::ResponseFcmTicket(fcm_ticket);
        let resp3 = KernelResponse::KernelShutdown(Vec::from("Hello, world!"));

        println!("{}", serde_json::to_string(&resp).unwrap());
        println!("{}", serde_json::to_string(&resp2).unwrap());
        println!("{}", serde_json::to_string(&resp3).unwrap());
    }

}