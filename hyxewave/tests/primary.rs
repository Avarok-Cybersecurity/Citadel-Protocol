#[cfg(test)]
mod tests {
    use hyxewave::ffi::{KernelResponse, DomainResponse};
    use hyxe_user::fcm::data_structures::FcmTicket;
    use hyxewave::command_handlers::peer::DeregisterResponse;

    #[test]
    fn misc() {
        let fcm_ticket = FcmTicket::new(123, 456, 789);
        let message = Vec::from("Hello, world!");
        let resp = KernelResponse::DomainSpecificResponse(DomainResponse::FcmMessage(hyxewave::ffi::FcmMessage{ fcm_ticket, message }));
        let resp2 = KernelResponse::ResponseFcmTicket(fcm_ticket);
        let resp3 = KernelResponse::KernelShutdown(Vec::from("Hello, world!"));
        let resp4 = KernelResponse::FcmError(fcm_ticket, Vec::from("Hello, world!"));
        let resp5 = KernelResponse::DomainSpecificResponse(DomainResponse::DeregisterResponse(DeregisterResponse { peer_cid: 123, implicated_cid: 456, ticket: 789, success: true }));

        println!("{}", serde_json::to_string(&resp).unwrap());
        println!("{}", serde_json::to_string(&resp2).unwrap());
        println!("{}", serde_json::to_string(&resp3).unwrap());
        println!("{}", serde_json::to_string(&resp4).unwrap());
        println!("{}", serde_json::to_string(&resp5).unwrap());
    }

}