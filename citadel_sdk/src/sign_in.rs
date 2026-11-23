//! Managing a post-quantum account's sign-in factors from an authenticated session: list, add a
//! security key, rename, remove, set the policy, set the password, replace the recovery phrase.
//!
//! Every change carries a fresh step-up (the account's factors, proven again, bound to the change)
//! except in a recovery console session (signed in with the phrase), which proves nothing again
//! and may only manage credentials (`SignInManagementOp::allowed_in_recovery`).
//!
//! Security keys need the server to name its relying party, with
//! `PqAuthServerSettings::with_security_key_rp_id`. With the `security-key` feature, the client's
//! keys are served by `SecurityKey::new(prompt).serve()` natively, or `SecurityKey::new().serve()`
//! in a browser; without it, serve the channel yourself:
//!
//! ```no_run
//! # use citadel_sdk::prelude::*;
//! # async fn f(conn: CitadelClientServerConnection<StackedRatchet>) -> Result<(), NetworkError> {
//! let (key, mut touches) = security_key_channel();
//! // Serve `touches` by running each request's WebAuthn ceremony with the PRF extension, then
//! // answering.
//! let step_up = SignInFactors::password("hunter2").with_security_key(key);
//! let op = SignInManagementOp::AddSecurityKey { label: "YubiKey".into() };
//! let added = conn.manage_sign_in(op, step_up).await?;
//! # Ok(()) }
//! ```

use crate::prelude::*;
use citadel_io::{error, ErrorCode};
use citadel_user::auth::pq::client::ClientManagement;
use citadel_user::auth::pq::messages::{ManagementDone, ManagementMessage, ServerOutcome};
use futures::StreamExt;

/// A change a session made to its own account's sign-in, and what became of the resume
/// credential its device held.
pub struct SignInChanged {
    pub outcome: SignInManagementOutcome,
    /// The credential re-bound to the account as it now stands, expiring when it always did.
    /// `None` when the server did not re-issue it: the one held is then of no further use if the
    /// change was to the password, the policy or the set of keys.
    pub resume: Option<ResumeCredential>,
}

#[async_trait]
pub trait SignInManagementExt {
    /// Runs one change. `step_up` holds the factors the account's policy asks for (and, for
    /// `AddSecurityKey`, the key channel that is asked to create the new key's credential).
    async fn manage_sign_in(
        &self,
        op: SignInManagementOp,
        step_up: SignInFactors,
    ) -> Result<SignInManagementOutcome, NetworkError>;

    /// Sets the account's password: a forgotten one from the recovery console (`step_up` empty),
    /// or a change from a full one (`step_up` the factors the policy asks for, the current
    /// password among them). The new password never leaves this device; the server gets a fresh
    /// factor's key, and the old password stops working at once. Other sessions keep running.
    async fn set_password<P: Into<SecBuffer> + Send>(
        &self,
        new_password: P,
        step_up: SignInFactors,
    ) -> Result<(), NetworkError>;

    /// As [`Self::manage_sign_in`] (or [`Self::set_password`], with `new_password`), from a
    /// device holding a resume credential: `step_up.resume` goes with the change, and the server
    /// hands back the same credential bound to the account as the change leaves it. Without
    /// this, a change to the password, the policy or the keys ends the device's own credential
    /// along with every other.
    async fn change_sign_in(
        &self,
        op: SignInManagementOp,
        new_password: Option<SecBuffer>,
        step_up: SignInFactors,
    ) -> Result<SignInChanged, NetworkError>;
}

#[async_trait]
impl<R: Ratchet> SignInManagementExt for CitadelClientServerConnection<R> {
    async fn manage_sign_in(
        &self,
        op: SignInManagementOp,
        step_up: SignInFactors,
    ) -> Result<SignInManagementOutcome, NetworkError> {
        Ok(run(self, op, step_up, None).await?.outcome)
    }

    async fn change_sign_in(
        &self,
        op: SignInManagementOp,
        new_password: Option<SecBuffer>,
        step_up: SignInFactors,
    ) -> Result<SignInChanged, NetworkError> {
        let password = new_password
            .as_ref()
            .map(ProposedCredentials::registration_password);
        run(self, op, step_up, password).await
    }

    async fn set_password<P: Into<SecBuffer> + Send>(
        &self,
        new_password: P,
        step_up: SignInFactors,
    ) -> Result<(), NetworkError> {
        let password = ProposedCredentials::registration_password(&new_password.into());
        let op = SignInManagementOp::SetPassword;
        match run(self, op, step_up, Some(password)).await?.outcome {
            SignInManagementOutcome::PasswordSet => Ok(()),
            _ => Err(error!(
                ErrorCode::PqSignInMalformed,
                "a password change's outcome"
            )),
        }
    }
}

async fn run<R: Ratchet>(
    conn: &CitadelClientServerConnection<R>,
    op: SignInManagementOp,
    step_up: SignInFactors,
    new_password: Option<SecBuffer>,
) -> Result<SignInChanged, NetworkError> {
    let cid = conn.cid;
    let remote = &conn.remote;
    let username = remote
        .account_manager()
        .get_username_by_cid(cid)
        .await?
        .ok_or_else(|| error!(ErrorCode::SessionClientNotLoaded))?;
    let (begin, client) = ClientManagement::begin(
        &username,
        op.clone(),
        step_up.password.as_ref(),
        new_password.as_ref(),
    )?;
    let held = step_up.resume.as_ref();
    let client = match held {
        Some(credential) => client.keeping(credential.present(citadel_user::misc::now_ms())?.0),
        None => client,
    };
    let challenge = match exchange(remote, cid, ManagementMessage::Begin(begin)).await? {
        ManagementMessage::Challenge(challenge) => challenge,
        other => return Err(unexpected(other)),
    };
    let key = step_up.security_key.as_ref();
    let ask = |purpose, request| async move {
        let key =
            key.ok_or_else(|| error!(ErrorCode::PqSignInFactorMissing, "a security key channel"))?;
        key.ask(purpose, request).await
    };
    let step_up_key = match ClientManagement::step_up_key_request(&challenge)? {
        Some(request) => Some(ask(SecurityKeyPurpose::StepUp, request).await?),
        None => None,
    };
    let new_key = match client.new_key_request(&challenge)? {
        Some(request) => Some(ask(SecurityKeyPurpose::Enrol, request).await?),
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
    let (outcome, grant) = match done {
        ManagementMessage::Done(ManagementDone::Done(outcome)) => (outcome, None),
        ManagementMessage::Done(ManagementDone::Reissued { outcome, grant }) => {
            (outcome, Some(grant))
        }
        other => return Err(unexpected(other)),
    };
    let resume = match (held, grant) {
        (Some(held), Some(grant)) => Some(held.reissued(grant)?),
        _ => None,
    };
    let outcome = match outcome {
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
        ServerOutcome::PasswordSet => SignInManagementOutcome::PasswordSet,
        ServerOutcome::RecoveryPhraseReplaced => match committed.into_recovery_phrase() {
            Some(seed) => SignInManagementOutcome::RecoveryPhrase(seed.words()),
            None => return Err(error!(ErrorCode::PqSignInMalformed, "a phrase's outcome")),
        },
    };
    Ok(SignInChanged { outcome, resume })
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
