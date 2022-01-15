use crate::sql::SqlConnectionHandler;
use std::net::ToSocketAddrs;
use tide::Server;
use std::sync::Arc;
use async_std::sync::Mutex;
use crate::github::GithubHandler;

pub struct WebHandler {
    app: Server<InnerState>
}

pub struct BackendHandler {
    sql_handler: SqlConnectionHandler,
    github_handler: GithubHandler
}

/// Wrap in a Mutex to ensure only one query gets executed at a time
type InnerState = Arc<Mutex<BackendHandler>>;

impl WebHandler {
    pub async fn new<S: Into<String>>(sqlite_addr: S, github_handler: GithubHandler) -> Result<Self, anyhow::Error> {
        let sql_handler = SqlConnectionHandler::new(sqlite_addr);
        sql_handler.init().await?;
        let mut app = tide::with_state(Arc::new(Mutex::new(BackendHandler { sql_handler, github_handler })));

        app.at("/customers/new").post(handlers::new_customer);
        app.at("/customers/remove").post(handlers::remove_customer);
        app.at("/customers/referrals").post(handlers::referral_count);
        app.at("/debug").get(handlers::debug);

        // TODO: create /customers/license for license retrieval IF CUSTOMER EXISTS
        // AND figure out git read-only credentialed access
        // octocrab rust Personal Access Token: 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

        Ok( Self { app } )
    }

    pub async fn listen<T: ToSocketAddrs>(self, addr: T) -> Result<(), anyhow::Error> {
        let addr = addr.to_socket_addrs()?.next().ok_or_else(||anyhow::Error::msg("No socket addrs"))?;
        self.app.listen(addr).await?;
        Ok(())
    }
}

mod handlers {
    use tide::Request;
    use crate::web::InnerState;
    use crate::definitions::rest::{Purchase, Customer};
    use crate::definitions::sql::CustomerEntry;

    pub async fn new_customer(mut req: Request<InnerState>) -> tide::Result {
        let mut purchase: Purchase = req.body_json().await?;
        let referrer = purchase.referral.take();
        let entry: CustomerEntry = purchase.into();
        let backend = req.state().lock().await;
        backend.sql_handler.new_customer(entry.clone(), referrer).await
            .map_err(|err| format!("An error occurred. Please contact customer service (ERR: {:?}", err))?;
        backend.github_handler.send_organization_invite(entry.github_id).await?;

        // TODO: Mint license here and return it
        Ok(format!("NEW_CUSTOMER request success: {:?}", entry).into())
    }

    pub async fn remove_customer(mut req: Request<InnerState>) -> tide::Result {
        let ref removal: Customer = req.body_json().await?;
        let backend = req.state().lock().await;
        let customer = backend.sql_handler.get_customer(removal).await?;
        backend.sql_handler.remove_customer(removal).await?;
        backend.github_handler.delete_member(customer.github_id).await?;

        Ok(format!("REMOVE request success").into())
    }

    pub async fn referral_count(mut req: Request<InnerState>) -> tide::Result {
        let ref removal: Customer = req.body_json().await?;
        let backend = req.state().lock().await;
        let count = backend.sql_handler.get_referral_count(removal).await?;

        #[derive(serde::Serialize)]
        struct ReferralCount {
            count: usize
        }

        Ok(serde_json::to_string(&ReferralCount{ count })?.into())
    }

    pub async fn debug(req: Request<InnerState>) -> tide::Result {
        let backend = req.state().lock().await;
        let output = backend.sql_handler.debug().await?;
        Ok(output.into())
    }

    fn wrap_error()
}