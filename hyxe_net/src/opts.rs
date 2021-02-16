use serde::{Serialize, Deserialize};

/// Passed to the HdpServer during the init phase
#[derive(Default, Clone)]
pub struct ServerAuxiliaryOptions {
    pub(crate) fcm_server_conn: Option<String>
}

impl ServerAuxiliaryOptions {
    pub fn with_fcm_server_api_key<T: Into<String>>(&mut self, api_key: T) -> &mut Self {
        self.fcm_server_conn = Some(api_key.into());
        self
    }

    pub fn build(&mut self) -> Self {
        Self { fcm_server_conn: self.fcm_server_conn.take() }
    }
}

/// Passed to the HdpServer during the init phase
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct ClientAuxiliaryOptions {
    pub(crate) reg_id: Option<String>
}

impl ClientAuxiliaryOptions {
    pub fn with_fcm_reg_id<T: Into<String>>(&mut self, reg_id: T) -> &mut Self {
        self.reg_id = Some(reg_id.into());
        self
    }

    pub fn build(&mut self) -> Self {
        Self { reg_id: self.reg_id.take() }
    }
}