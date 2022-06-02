use crate::prelude::{PeerSignal, Remote, PeerResponse, NetworkError};

/// Given the `input_signal` from the peer, this function returns a valid
/// signal to accept a peer registration
pub async fn peer_register<T: Remote>(input_signal: PeerSignal, accept: bool, remote: &T) -> Result<PeerSignal, NetworkError> {
    if let PeerSignal::PostRegister(v_conn, username, username_opt, ticket, None, fcm) = input_signal {
        let resp = if accept {
            let username = remote.account_manager().get_username_by_cid(v_conn.get_original_target_cid()).await
                .map_err(|err| NetworkError::Generic(err.into_string()))?
                .ok_or_else(|| NetworkError::InternalError("Unable to find local username implied by signal"))?;
            PeerResponse::Accept(Some(username))
        } else {
            PeerResponse::Decline
        };

        // v_conn must be reversed
        Ok(PeerSignal::PostRegister(v_conn.reverse(), username, username_opt, ticket, Some(resp), fcm))
    } else {
        Err(NetworkError::InternalError("Input signal is not a PostRegister"))
    }
}