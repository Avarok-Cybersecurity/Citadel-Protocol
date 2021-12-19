use sqlx::{SqliteConnection, Connection, Executor, Arguments, Row};
use crate::definitions::sql::{CustomerEntry, ReferralEntry};
use sqlx::sqlite::{SqliteArguments, SqliteRow};
use crate::definitions::rest::Customer;

pub struct SqlConnectionHandler {
    url: String
}

impl SqlConnectionHandler {
    pub fn new<T: Into<String>>(url: T) -> Self {
        Self { url: url.into()}
    }

    pub async fn init(&self) -> Result<(), anyhow::Error> {
        let ref mut conn = self.open_connection().await?;
        let cmd = format!("CREATE TABLE IF NOT EXISTS customers(uuid VARCHAR(64) NOT NULL, name TEXT, email TEXT, purchase_date_utc TEXT, PRIMARY KEY (uuid))");
        let cmd2 = format!("CREATE TABLE IF NOT EXISTS referrals(uuid VARCHAR(64), uuid_referrent VARCHAR(64), CONSTRAINT fk_cid FOREIGN KEY (uuid) REFERENCES customers(uuid) ON DELETE CASCADE)");

        let _ = conn.execute("DROP TRIGGER IF EXISTS post_customer_delete").await?;

        let cmd3 = "CREATE TRIGGER post_customer_delete AFTER DELETE ON customers FOR EACH ROW BEGIN DELETE FROM referrals WHERE referrals.uuid = old.uuid OR referrals.uuid_referrent = old.uuid; END";
        let _ = conn.execute(&*cmd).await?;
        let _ = conn.execute(&*cmd2).await?;
        let _ = conn.execute(&*cmd3).await?;

        Ok(())
    }

    pub async fn new_customer(&self, customer: CustomerEntry, referrer: Option<String>) -> Result<(), anyhow::Error> {
        let cmd = "INSERT INTO customers VALUES(?, ?, ?, ?) ON CONFLICT(uuid) DO UPDATE SET uuid=excluded.uuid, name=excluded.name, email=excluded.email, purchase_date_utc=excluded.purchase_date_utc";
        let ref mut conn = self.open_connection().await?;

        let mut args = SqliteArguments::default();
        args.add(customer.uuid.clone());
        args.add(customer.name);
        args.add(customer.email);
        args.add(customer.purchase_date_utc);

        let _ = sqlx::query_with(cmd, args).execute(&mut *conn).await?;

        if let Some(referrer) = referrer {
            let cmd = "INSERT INTO referrals VALUES(?, ?)";
            let _ = sqlx::query(cmd).bind(referrer).bind(customer.uuid).execute(&mut *conn).await?;
        }

        Ok(())
    }

    pub async fn remove_customer(&self, customer: Customer) -> Result<(), anyhow::Error> {
        let cmd = "DELETE FROM customers WHERE uuid = ?";
        let ref mut sql = self.open_connection().await?;
        let result = sqlx::query(cmd).bind(customer.uuid).execute(&mut *sql).await?;
        if result.rows_affected() != 0 {
            Ok(())
        } else {
            Err(anyhow::Error::msg(format!("Unable to remove customer: {:?}", result)))
        }
    }

    pub async fn get_referral_count(&self, customer: Customer) -> Result<usize, anyhow::Error> {
        let ref mut conn = self.open_connection().await?;
        let query: SqliteRow = sqlx::query("SELECT COUNT(*) as count FROM referrals WHERE uuid = ?").bind(customer.uuid).fetch_one(&mut *conn).await?;
        let count = query.get::<i64, _>("count") as usize;

        Ok(count)
    }

    pub async fn debug(&self) -> Result<String, anyhow::Error> {
        let cmd = "SELECT * FROM customers";
        let cmd2 = "SELECT * FROM referrals";

        let ref mut conn = self.open_connection().await?;
        let query = sqlx::query_as::<_, CustomerEntry>(cmd).fetch_all(&mut *conn).await?;
        let query2 = sqlx::query_as::<_, ReferralEntry>(cmd2).fetch_all(&mut *conn).await?;

        Ok(format!("Customers:\n{:?}\n\nReferrals:\n{:?}\n\n", query, query2))
    }

    async fn open_connection(&self) -> Result<SqliteConnection, anyhow::Error> {
        Ok(SqliteConnection::connect(self.url.as_str()).await?)
    }
}