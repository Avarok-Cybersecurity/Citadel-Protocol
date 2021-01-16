use crate::error::{KissCode, ProtocolError, SynchroniztationError};
use crate::packet::{LeapIndicator, Mode, Packet, ReferenceIdentifier, SntpTimestamp};
use chrono::{DateTime, Duration, Utc};

/// Results of a synchronization.
///
/// If you just simply need a fairly accurate SNTP time then check the `datetime()` method. Other methods
/// provide more detailed information received from the server and might need deeper knwoledge about
/// SNTP protocol internals.
#[derive(Debug, Clone)]
pub struct SynchronizationResult {
    clock_offset: Duration,
    round_trip_delay: Duration,
    reference_identifier: ReferenceIdentifier,
    leap_indicator: LeapIndicator,
    stratum: u8,
}

impl SynchronizationResult {
    /// Returns with the offset between the server and local clock.
    ///
    /// It is a signed duration, negative value means the local clock is ahead.
    ///
    /// # Example
    ///
    /// Print the synchronized local time using clock offset:
    /// ```no_run
    /// use rsntp::SntpClient;
    /// use chrono::Local;
    ///
    /// let client = SntpClient::new();
    /// let result = client.synchronize("pool.ntp.org").unwrap();
    ///
    /// println!("Local time: {}", Local::now() + result.clock_offset());
    /// ```
    pub fn clock_offset(&self) -> Duration {
        self.clock_offset
    }

    /// Returns with the round trip delay
    ///
    /// The time is needed for SNTP packets to travel back and forth between the host and the server.
    /// It is a signed value but negative values should not be possible in client mode
    /// (which is currently always used by the library).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rsntp::SntpClient;
    /// use chrono::Local;
    ///
    /// let client = SntpClient::new();
    /// let result = client.synchronize("pool.ntp.org").unwrap();
    ///
    /// println!("RTT: {} ms", result.round_trip_delay().num_milliseconds());
    /// ```
    pub fn round_trip_delay(&self) -> Duration {
        self.round_trip_delay
    }

    /// Returns with the server reference identifier.
    ///
    /// This identifies the synchronizaion source of the server. For primary servers (startum = 1) this is a four
    /// byte ASCII string, for secondary IPv4 servers (startum >= 2) this is an IP address.
    ///   
    /// # Example
    ///
    /// ```no_run
    /// use rsntp::SntpClient;
    /// use chrono::Local;
    ///
    /// let client = SntpClient::new();
    /// let result = client.synchronize("pool.ntp.org").unwrap();
    ///
    /// println!("Server reference identifier: {}", result.reference_identifier());
    /// ```
    pub fn reference_identifier(&self) -> &ReferenceIdentifier {
        &self.reference_identifier
    }

    /// Returns with the current UTC date and time, based on the synchronized SNTP timestamp.
    ///
    /// This is the current UTC date and time, calculated by adding clock offset the UTC time. To be accurate,
    /// use the returned value immediately after the call of this function.
    ///
    /// # Example
    ///
    /// Calcuating synchronized local time:
    /// ```no_run
    /// use rsntp::SntpClient;
    /// use chrono::{DateTime, Local};
    ///
    /// let client = SntpClient::new();
    /// let result = client.synchronize("pool.ntp.org").unwrap();
    ///
    /// let local_time: DateTime<Local> = DateTime::from(result.datetime());
    /// ```
    pub fn datetime(&self) -> DateTime<Utc> {
        Utc::now() + self.clock_offset
    }

    /// Returns with the leap indicator
    ///
    /// This is the leap indicator returned by the server. It is a warning of an impending leap second to be
    /// inserted/deleted in the last minute of the current day.
    ///
    /// It is set before 23:59 on the day of insertion and reset after 00:00 on the following day. This causes
    /// the number of seconds (rollover interval) in the day of insertion to be increased or decreased by one.
    ///
    /// # Example
    ///
    /// Printing leap indicator:
    ///
    /// ```no_run
    /// use rsntp::SntpClient;
    /// use chrono::{DateTime, Local};
    ///
    /// let client = SntpClient::new();
    /// let result = client.synchronize("pool.ntp.org").unwrap();
    ///
    /// println!("Leap indicator: {:?}", result.leap_indicator());
    /// ```
    pub fn leap_indicator(&self) -> LeapIndicator {
        self.leap_indicator
    }

    /// Returns with the server stratum
    ///
    /// NTP uses a hierarchical, semi-layered system of time sources. Each level of this hierarchy is
    /// termed a stratum and is assigned a number starting with zero for the reference clock at the top.
    /// A server synchronized to a stratum n server runs at stratum n + 1
    ///
    /// Values defined as:
    /// *  1 - Primary reference (e.g., calibrated atomic clock, radio clock, etc...)
    /// *  2..15 - Secondary reference (via NTP, calculated as the stratum of system peer plus one)
    /// *  16 - Unsynchronized
    /// *  16..255 - Reserved
    ///
    /// # Example
    ///
    /// ```no_run
    /// use rsntp::SntpClient;
    /// use chrono::{DateTime, Local};
    ///
    /// let client = SntpClient::new();
    /// let result = client.synchronize("pool.ntp.org").unwrap();
    ///
    /// assert!(result.stratum() >= 1);
    /// ```
    pub fn stratum(&self) -> u8 {
        self.stratum
    }
}

pub struct Request {
    packet: Packet,
}

impl Request {
    pub fn new() -> Request {
        Request {
            packet: Packet {
                li: LeapIndicator::NoWarning,
                mode: Mode::Client,
                stratum: 0,
                reference_identifier: ReferenceIdentifier::Empty,
                reference_timestamp: SntpTimestamp::zero(),
                originate_timestamp: SntpTimestamp::zero(),
                receive_timestamp: SntpTimestamp::zero(),
                transmit_timestamp: SntpTimestamp::from_datetime(Utc::now()),
            },
        }
    }

    pub fn as_bytes(&self) -> [u8; Packet::ENCODED_LEN] {
        self.packet.to_bytes()
    }

    fn into_packet(self) -> Packet {
        self.packet
    }
}

pub struct Reply {
    request: Packet,
    reply: Packet,
    reply_timestamp: DateTime<Utc>,
}

impl Reply {
    pub fn new(request: Request, reply: Packet) -> Reply {
        Reply {
            request: request.into_packet(),
            reply,
            reply_timestamp: Utc::now(),
        }
    }

    fn check(&self) -> Result<(), ProtocolError> {
        if self.reply.stratum == 0 {
            return Err(ProtocolError::KissODeath(KissCode::new(
                &self.reply.reference_identifier,
            )));
        }

        if self.reply.originate_timestamp != self.request.transmit_timestamp {
            return Err(ProtocolError::InvalidOriginateTimestamp);
        }

        if self.reply.transmit_timestamp.is_zero() {
            return Err(ProtocolError::InvalidTransmitTimestamp);
        }

        if self.reply.mode != Mode::Server && self.reply.mode != Mode::Broadcast {
            return Err(ProtocolError::InvalidMode);
        }
        Ok(())
    }

    pub fn process(self) -> Result<SynchronizationResult, SynchroniztationError> {
        self.check()?;

        let originate_ts = self.reply.originate_timestamp.to_datetime();
        let transmit_ts = self.reply.transmit_timestamp.to_datetime();
        let receive_ts = self.reply.receive_timestamp.to_datetime();
        let round_trip_delay = (self.reply_timestamp - originate_ts) - (transmit_ts - receive_ts);
        let clock_offset = ((receive_ts - originate_ts) + (transmit_ts - self.reply_timestamp)) / 2;
        Ok(SynchronizationResult {
            round_trip_delay,
            clock_offset,
            reference_identifier: self.reply.reference_identifier.clone(),
            leap_indicator: self.reply.li,
            stratum: self.reply.stratum,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! assert_between {
        ($var: expr, $lower: expr, $upper: expr) => {
            if $var < $lower || $var > $upper {
                panic!(
                    "Assertion failed, {:?} is not between {:?} and {:?}",
                    $var, $lower, $upper
                );
            }
        };
    }

    #[test]
    fn basic_synchronization_works() {
        let request = Request::new();

        std::thread::sleep(Duration::milliseconds(100).to_std().unwrap());
        let now = Utc::now();
        std::thread::sleep(Duration::milliseconds(100).to_std().unwrap());

        let reply_packet = Packet {
            li: LeapIndicator::NoWarning,
            mode: Mode::Server,
            stratum: 1,
            reference_identifier: ReferenceIdentifier::new_ascii([0x4c, 0x4f, 0x43, 0x4c]).unwrap(),
            reference_timestamp: SntpTimestamp::from_datetime(now - Duration::days(1)),
            originate_timestamp: request.packet.transmit_timestamp,
            receive_timestamp: SntpTimestamp::from_datetime(now - Duration::milliseconds(500)),
            transmit_timestamp: SntpTimestamp::from_datetime(now - Duration::milliseconds(500)),
        };

        let reply = Reply::new(request, reply_packet);

        let result = reply.process().unwrap();

        assert_between!(result.clock_offset().num_milliseconds(), -510, -490);
        assert_between!(result.round_trip_delay().num_milliseconds(), 190, 210);

        assert_eq!(result.reference_identifier().to_string(), "LOCL");
        assert_eq!(result.leap_indicator(), LeapIndicator::NoWarning);
        assert_eq!(result.stratum(), 1);
    }

    #[test]
    fn sync_fails_if_reply_originate_ts_does_not_match_request_transmit_ts() {
        let request = Request::new();
        let now = Utc::now();

        let reply_packet = Packet {
            li: LeapIndicator::NoWarning,
            mode: Mode::Server,
            stratum: 1,
            reference_identifier: ReferenceIdentifier::new_ascii([0x4c, 0x4f, 0x43, 0x4c]).unwrap(),
            reference_timestamp: SntpTimestamp::from_datetime(now - Duration::days(1)),
            originate_timestamp: SntpTimestamp::from_datetime(now),
            receive_timestamp: SntpTimestamp::from_datetime(now - Duration::milliseconds(500)),
            transmit_timestamp: SntpTimestamp::from_datetime(now - Duration::milliseconds(500)),
        };

        let reply = Reply::new(request, reply_packet);

        let result = reply.process();

        assert!(result.is_err());
    }

    #[test]
    fn sync_fails_if_reply_contains_zero_transmit_timestamp() {
        let request = Request::new();
        let now = Utc::now();

        let reply_packet = Packet {
            li: LeapIndicator::NoWarning,
            mode: Mode::Server,
            stratum: 1,
            reference_identifier: ReferenceIdentifier::new_ascii([0x4c, 0x4f, 0x43, 0x4c]).unwrap(),
            reference_timestamp: SntpTimestamp::from_datetime(now - Duration::days(1)),
            originate_timestamp: request.packet.transmit_timestamp,
            receive_timestamp: SntpTimestamp::from_datetime(now - Duration::milliseconds(500)),
            transmit_timestamp: SntpTimestamp::zero(),
        };

        let reply = Reply::new(request, reply_packet);

        let result = reply.process();

        assert!(result.is_err());
    }

    #[test]
    fn sync_fails_if_reply_contains_wrong_mode() {
        let request = Request::new();
        let now = Utc::now();

        let reply_packet = Packet {
            li: LeapIndicator::NoWarning,
            mode: Mode::Client,
            stratum: 1,
            reference_identifier: ReferenceIdentifier::new_ascii([0x4c, 0x4f, 0x43, 0x4c]).unwrap(),
            reference_timestamp: SntpTimestamp::from_datetime(now - Duration::days(1)),
            originate_timestamp: request.packet.transmit_timestamp,
            receive_timestamp: SntpTimestamp::from_datetime(now - Duration::milliseconds(500)),
            transmit_timestamp: SntpTimestamp::from_datetime(now - Duration::milliseconds(500)),
        };

        let reply = Reply::new(request, reply_packet);

        let result = reply.process();

        assert!(result.is_err());
    }

    #[test]
    fn sync_fails_if_kiss_o_death_received() {
        let request = Request::new();
        let now = Utc::now();

        let reply_packet = Packet {
            li: LeapIndicator::NoWarning,
            mode: Mode::Server,
            stratum: 0,
            reference_identifier: ReferenceIdentifier::new_ascii([0x52, 0x41, 0x54, 0x45]).unwrap(),
            reference_timestamp: SntpTimestamp::from_datetime(now - Duration::days(1)),
            originate_timestamp: request.packet.transmit_timestamp,
            receive_timestamp: SntpTimestamp::from_datetime(now - Duration::milliseconds(500)),
            transmit_timestamp: SntpTimestamp::from_datetime(now - Duration::milliseconds(500)),
        };

        let reply = Reply::new(request, reply_packet);

        let err = reply.process().unwrap_err();

        if let SynchroniztationError::ProtocolError(ProtocolError::KissODeath(
            KissCode::RateExceeded,
        )) = err
        {
            // pass
        } else {
            panic!("Wrong error received");
        }
    }
}
