use crate::proto::remote::Ticket;

/// For keeping track of deregistration processes
#[derive(Default)]
pub struct DeRegisterState {
    pub(crate) last_packet_time: Option<i64>,
    pub(crate) in_progress: bool,
    pub(crate) current_ticket: Option<Ticket>,
}

impl DeRegisterState {
    /// run this when it begins
    pub fn on_init(&mut self, timestamp: i64, ticket: Ticket) {
        self.in_progress = true;
        self.last_packet_time = Some(timestamp);
        self.current_ticket = Some(ticket);
    }
}
