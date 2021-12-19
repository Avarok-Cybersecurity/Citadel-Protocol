pub mod sql {

    #[derive(sqlx::FromRow, Debug, Clone)]
    pub struct CustomerEntry {
        pub uuid: String,
        pub name: String,
        pub email: String,
        pub purchase_date_utc: String
    }

    #[derive(sqlx::FromRow, Debug)]
    pub struct ReferralEntry {
        // The customer who made the referral
        pub uuid: String,
        // the customer who was referred to by uuid_referral
        pub uuid_referrent: String
    }
}

pub mod rest {
    use serde::Deserialize;

    #[derive(Deserialize, Debug)]
    pub struct Purchase {
        pub uuid: String,
        pub name: String,
        pub email: String,
        // points to the uuid
        pub referral: Option<String>
    }

    #[derive(Deserialize, Debug)]
    pub struct Customer {
        pub uuid: String
    }
}

pub mod impls {
    use crate::definitions::rest::Purchase;
    use crate::definitions::sql::CustomerEntry;
    use sqlx::types::time::Date;

    impl From<Purchase> for CustomerEntry {
        fn from(purchase: Purchase) -> Self {
            Self {
                uuid: purchase.uuid,
                name: purchase.name,
                email: purchase.email,
                purchase_date_utc: Date::today().to_string()
            }
        }
    }
}