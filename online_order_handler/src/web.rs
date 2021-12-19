use crate::sql::SqlConnectionHandler;
use std::net::ToSocketAddrs;
use tide::Server;
use std::sync::Arc;
use async_std::sync::Mutex;

pub struct WebHandler {
    app: Server<InnerState>
}

/// Wrap in a Mutex to ensure only one query gets executed at a time
type InnerState = Arc<Mutex<SqlConnectionHandler>>;

impl WebHandler {
    pub async fn new<S: Into<String>>(sqlite_addr: S) -> Result<Self, anyhow::Error> {
        let sqlite_conn = SqlConnectionHandler::new(sqlite_addr);
        sqlite_conn.init().await?;
        let mut app = tide::with_state(Arc::new(Mutex::new(sqlite_conn)));

        app.at("/customers/new").post(handlers::new_customer);
        app.at("/customers/remove").post(handlers::remove_customer);
        app.at("/customers/referrals").post(handlers::referral_count);
        app.at("/debug").get(handlers::debug);


        Ok( Self { app } )
    }

    pub async fn listen<T: ToSocketAddrs>(self, addr: T) -> Result<(), anyhow::Error> {
        let WebHandler {
            app
        } = self;

        let addr = addr.to_socket_addrs()?.next().ok_or_else(||anyhow::Error::msg("No socket addrs"))?;
        app.listen(addr).await?;
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
        let sql = req.state().lock().await;
        sql.new_customer(entry.clone(), referrer).await?;

        // TODO: Mint license here and return it
        Ok(format!("NEW_CUSTOMER request success: {:?}", entry).into())
    }

    pub async fn remove_customer(mut req: Request<InnerState>) -> tide::Result {
        let removal: Customer = req.body_json().await?;
        let sql = req.state().lock().await;
        sql.remove_customer(removal).await?;

        Ok(format!("REMOVE request success").into())
    }

    pub async fn referral_count(mut req: Request<InnerState>) -> tide::Result {
        let removal: Customer = req.body_json().await?;
        let sql = req.state().lock().await;
        let count = sql.get_referral_count(removal).await?;

        #[derive(serde::Serialize)]
        struct ReferralCount {
            count: usize
        }

        Ok(serde_json::to_string(&ReferralCount{ count })?.into())
    }

    pub async fn debug(req: Request<InnerState>) -> tide::Result {
        let sql = req.state().lock().await;
        let output = sql.debug().await?;
        Ok(output.into())
    }
}