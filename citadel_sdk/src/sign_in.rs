//! Managing a post-quantum account's sign-in factors from an authenticated session: list, add a
//! security key, rename, remove, set the policy, regenerate the recovery codes.
//!
//! Every change carries a fresh step-up (the account's factors, proven again, bound to the change)
//! except in a session signed in with a recovery code, which may only add a key and set the policy.
//!
//! ```no_run
//! # use citadel_sdk::prelude::*;
//! # async fn f(conn: CitadelClientServerConnection<StackedRatchet>) -> Result<(), NetworkError> {
//! let (key, mut touches) = security_key_channel();
//! // Serve `touches` by running WebAuthn `get` with the PRF extension, then answering.
//! let step_up = SignInFactors::password("hunter2").with_security_key(key);
//! let op = SignInManagementOp::AddSecurityKey { credential_id: vec![1, 2, 3], label: "YubiKey".into() };
//! let added = conn.manage_sign_in(op, step_up).await?;
//! # Ok(()) }
//! ```

use crate::prelude::*;
use citadel_io::{error, ErrorCode};
use citadel_user::auth::pq::client::ClientManagement;
use citadel_user::auth::pq::messages::{ManagementDone, ManagementMessage, ServerOutcome};
use futures::StreamExt;

#[async_trait]
pub trait SignInManagementExt {
    /// Runs one change. `step_up` holds the factors the account's policy asks for (and, for
    /// `AddSecurityKey`, the key channel that is asked for the new key's PRF output).
    async fn manage_sign_in(
        &self,
        op: SignInManagementOp,
        step_up: SignInFactors,
    ) -> Result<SignInManagementOutcome, NetworkError>;
}

#[async_trait]
impl<R: Ratchet> SignInManagementExt for CitadelClientServerConnection<R> {
    async fn manage_sign_in(
        &self,
        op: SignInManagementOp,
        step_up: SignInFactors,
    ) -> Result<SignInManagementOutcome, NetworkError> {
        let cid = self.cid;
        let remote = &self.remote;
        let username = remote
            .account_manager()
            .get_username_by_cid(cid)
            .await?
            .ok_or_else(|| error!(ErrorCode::SessionClientNotLoaded))?;
        let (begin, client) =
            ClientManagement::begin(&username, op.clone(), step_up.password.as_ref())?;
        let challenge = match exchange(remote, cid, ManagementMessage::Begin(begin)).await? {
            ManagementMessage::Challenge(challenge) => challenge,
            other => return Err(unexpected(other)),
        };
        let key = step_up.security_key.as_ref();
        let ask = |purpose, request| async move {
            let key = key.ok_or_else(|| {
                error!(ErrorCode::PqSignInFactorMissing, "a security key channel")
            })?;
            key.ask(purpose, request).await
        };
        let step_up_key = match ClientManagement::step_up_key_request(&challenge) {
            Some(request) => Some(ask(SecurityKeyPurpose::StepUp, request).await?),
            None => None,
        };
        let new_key = match client.new_key_request(&challenge) {
            Some(request) => Some(ask(SecurityKeyPurpose::Enrol, request).await?.prf),
            None => None,
        };
        let (commit, committed) = client.commit(cid, &challenge, step_up_key, new_key).await?;
        let done = match exchange(remote, cid, ManagementMessage::Commit(commit)).await? {
            ManagementMessage::EnrolChallenge(enrol) => {
                let proof = committed.enrol_proof(cid, &enrol)?;
                exchange(remote, cid, ManagementMessage::EnrolProof(proof)).await?
            }
            other => other,
        };
        let outcome = match done {
            ManagementMessage::Done(ManagementDone::Done(outcome)) => outcome,
            other => return Err(unexpected(other)),
        };
        Ok(match outcome {
            ServerOutcome::Credentials {
                policy,
                credentials,
            } => SignInManagementOutcome::Credentials {
                policy,
                credentials,
            },
            ServerOutcome::Added { id } => SignInManagementOutcome::Added { id },
            ServerOutcome::Renamed => SignInManagementOutcome::Renamed,
            ServerOutcome::Removed => SignInManagementOutcome::Removed,
            ServerOutcome::PolicySet => SignInManagementOutcome::PolicySet,
            ServerOutcome::RecoveryCodesReplaced => SignInManagementOutcome::RecoveryCodes(
                committed
                    .into_recovery_codes()
                    .iter()
                    .map(|code| code.display().to_string())
                    .collect(),
            ),
        })
    }
}

fn unexpected(message: ManagementMessage) -> NetworkError {
    match message {
        ManagementMessage::Done(ManagementDone::Refused(reason)) => {
            error!(ErrorCode::PqSignInPolicy, reason)
        }
        _ => error!(
            ErrorCode::PqSignInMalformed,
            "an out-of-order management reply"
        ),
    }
}

/// One request and its reply, over the session's signal channel.
async fn exchange<R: Ratchet>(
    remote: &ClientServerRemote<R>,
    cid: u64,
    message: ManagementMessage,
) -> Result<ManagementMessage, NetworkError> {
    let request = NodeRequest::PeerCommand(PeerCommand {
        session_cid: cid,
        command: PeerSignal::SignInManagement {
            session_cid: cid,
            message,
        },
    });
    let mut replies = remote.send_callback_subscription(request).await?;
    while let Some(reply) = replies.next().await {
        if let NodeResult::PeerEvent(PeerEvent {
            event: PeerSignal::SignInManagement { message, .. },
            ..
        }) = reply.into_result()?
        {
            return Ok(message);
        }
    }
    Err(error!(
        ErrorCode::RemoteKernelStreamDied,
        "sign-in management"
    ))
}
