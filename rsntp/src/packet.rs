use crate::error::ProtocolError;
use chrono::{DateTime, TimeZone, Utc};
use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SntpTimestamp(u128);

impl SntpTimestamp {
    const UNIX_EPOCH: u128 = 2_208_988_800;

    pub fn zero() -> SntpTimestamp {
        SntpTimestamp(0)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    fn from_bytes(bytes: [u8; 8]) -> SntpTimestamp {
        let timestamp = u64::from_be_bytes(bytes);

        if (timestamp & 0x8000_0000_0000_0000) == 0 {
            SntpTimestamp(timestamp as u128 + 0x0001_0000_0000_0000_0000)
        } else {
            SntpTimestamp(timestamp as u128)
        }
    }

    pub fn from_datetime<T: TimeZone>(datetime: DateTime<T>) -> SntpTimestamp {
        let seconds = datetime.timestamp() as i128 + SntpTimestamp::UNIX_EPOCH as i128;
        let subsec_nanos = ((datetime.timestamp_subsec_nanos() as u128) << 32) / 1_000_000_000;

        SntpTimestamp(((seconds as u128) << 32) + subsec_nanos)
    }

    fn to_bytes(&self) -> [u8; 8] {
        assert!(self.0 < 0x0002_0000_0000_0000_0000);

        let timestamp = if self.0 < 0x0001_0000_0000_0000_0000 {
            self.0 as u64
        } else {
            (self.0 & 0x7fff_ffff_ffff_ffff) as u64
        };

        timestamp.to_be_bytes()
    }

    pub fn to_datetime(&self) -> DateTime<Utc> {
        let secs = (self.0 >> 32) as i64 - (SntpTimestamp::UNIX_EPOCH as i64);
        let nsecs: u32 = (((self.0 & 0xffff_ffff) * 1_000_000_000) >> 32)
            .try_into()
            .unwrap();

        Utc.timestamp(secs, nsecs)
    }
}

/// Leap indicator
///
/// Indicator of an impending leap second to be inserted/deleted in the last minute of the current day.
///
/// The warning is set before 23:59 on the day of insertion and reset after 00:00 on the following day. This
/// causes the number of seconds (rollover interval) in the day of insertion to be increased or decreased by one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum LeapIndicator {
    /// No warning, i.e. no leap second
    NoWarning,
    /// The last minute of the day has 61 seconds
    LastMinuteHas61Seconds,
    /// The last minute of the day has 59 seconds
    LastMinuteHas59Seconds,
    /// Alarm condition, the clock is not synchronized
    AlarmCondition,
}

impl LeapIndicator {
    fn from_u8(raw: u8) -> Result<LeapIndicator, ProtocolError> {
        match raw {
            0 => Ok(LeapIndicator::NoWarning),
            1 => Ok(LeapIndicator::LastMinuteHas59Seconds),
            2 => Ok(LeapIndicator::LastMinuteHas61Seconds),
            3 => Ok(LeapIndicator::AlarmCondition),
            _ => Err(ProtocolError::InvalidLeapIndicator),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            LeapIndicator::NoWarning => 0,
            LeapIndicator::LastMinuteHas59Seconds => 1,
            LeapIndicator::LastMinuteHas61Seconds => 2,
            LeapIndicator::AlarmCondition => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Client,
    Server,
    Broadcast,
}

impl Mode {
    fn from_u8(raw: u8) -> Result<Mode, ProtocolError> {
        match raw {
            3 => Ok(Mode::Client),
            4 => Ok(Mode::Server),
            5 => Ok(Mode::Broadcast),
            _ => Err(ProtocolError::InvalidMode),
        }
    }

    fn to_u8(self) -> u8 {
        match self {
            Mode::Client => 3,
            Mode::Server => 4,
            Mode::Broadcast => 5,
        }
    }
}

/// Identifies the particular reference source.  
///
/// * For primary servers, the value is a four-character ASCII string. For possible values see RFC4330, section 4.
/// * For IPv4 secondary servers, the value is the IPv4 address of the synchronization source.
/// * For IPv6 secondary servers, the value is the first 32 bits of the MD5 hash of the IPv6 address of the
///   synchronization source (IPv6 not yet supported by the library)
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum ReferenceIdentifier {
    /// No reference identifier. Currently should not used in public API
    Empty,
    /// ASCII string identifying a primary server
    ASCII(String),
    /// IPv4 address, identifiying an IPv4 secondary server
    IpAddress(IpAddr),
    /// MD5 hash of an IPv6 address, identifying an IPv6 server (not yet supported)
    MD5Hash(u32),
}

impl ReferenceIdentifier {
    pub(crate) fn new_ascii(raw: [u8; 4]) -> Result<ReferenceIdentifier, ProtocolError> {
        if !raw.is_ascii() {
            return Err(ProtocolError::InvalidReferenceIdentifier);
        }

        Ok(ReferenceIdentifier::ASCII(
            String::from_utf8_lossy(&raw)
                .trim_end_matches('\u{0}')
                .into(),
        ))
    }

    pub(crate) fn new_ipv4_address(raw: [u8; 4]) -> Result<ReferenceIdentifier, ProtocolError> {
        Ok(ReferenceIdentifier::IpAddress(IpAddr::from(raw)))
    }

    fn is_empty(&self) -> bool {
        match self {
            ReferenceIdentifier::Empty => true,
            _ => false,
        }
    }
}

impl Display for ReferenceIdentifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ReferenceIdentifier::Empty => Ok(()),
            ReferenceIdentifier::ASCII(s) => write!(f, "{}", s),
            ReferenceIdentifier::IpAddress(addr) => write!(f, "{}", addr.to_string()),
            ReferenceIdentifier::MD5Hash(_hash) => unimplemented!(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub li: LeapIndicator,
    pub mode: Mode,
    pub stratum: u8,
    pub reference_identifier: ReferenceIdentifier,
    pub reference_timestamp: SntpTimestamp,
    pub originate_timestamp: SntpTimestamp,
    pub receive_timestamp: SntpTimestamp,
    pub transmit_timestamp: SntpTimestamp,
}

impl Packet {
    pub const ENCODED_LEN: usize = 48;

    pub fn from_bytes(data: &[u8]) -> Result<Packet, ProtocolError> {
        if data.len() < Packet::ENCODED_LEN {
            return Err(ProtocolError::PacketIsTooShort);
        }

        let version = (data[0] >> 3) & 0x07;

        if version != 4 {
            return Err(ProtocolError::InvalidPacketVersion);
        }

        let li = LeapIndicator::from_u8(data[0] >> 6)?;
        let mode = Mode::from_u8(data[0] & 0x07)?;
        let stratum = data[1];

        let raw_reference_identifier = data[12..16].try_into().unwrap();

        let reference_identifier = if stratum == 0 || stratum == 1 {
            ReferenceIdentifier::new_ascii(raw_reference_identifier)?
        } else {
            ReferenceIdentifier::new_ipv4_address(raw_reference_identifier)?
        };

        Ok(Packet {
            li,
            mode,
            stratum,
            reference_identifier,
            reference_timestamp: SntpTimestamp::from_bytes(data[16..24].try_into().unwrap()),
            originate_timestamp: SntpTimestamp::from_bytes(data[24..32].try_into().unwrap()),
            receive_timestamp: SntpTimestamp::from_bytes(data[32..40].try_into().unwrap()),
            transmit_timestamp: SntpTimestamp::from_bytes(data[40..48].try_into().unwrap()),
        })
    }

    pub fn to_bytes(&self) -> [u8; Packet::ENCODED_LEN] {
        const SNTP_VERSION_CONSTANT: u8 = 0x20;
        let mut binary = [0; Packet::ENCODED_LEN];

        binary[0] = self.li.to_u8() << 6 | SNTP_VERSION_CONSTANT | self.mode.to_u8();
        binary[1] = self.stratum;

        assert!(
            self.reference_identifier.is_empty(),
            "Reference identifier should be empty for client packets"
        );

        binary[16..24].copy_from_slice(&self.reference_timestamp.to_bytes());
        binary[24..32].copy_from_slice(&self.originate_timestamp.to_bytes());
        binary[32..40].copy_from_slice(&self.receive_timestamp.to_bytes());
        binary[40..48].copy_from_slice(&self.transmit_timestamp.to_bytes());

        binary
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_timestamp_converts_to_zero_raw() {
        assert_eq!(
            SntpTimestamp::zero().to_bytes(),
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn zero_timestamp_is_zero() {
        assert!(SntpTimestamp::zero().is_zero());
    }

    #[test]
    fn timestamp_created_from_bytes_converts_to_the_same_raw() {
        let before_2036 = [0xc5, 0x02, 0x03, 0x4c, 0x36, 0xbb, 0xa9, 0x8e];
        let after_2036 = [0x08, 0x1D, 0xD1, 0x80, 0x80, 0x00, 0x00, 0x00];

        assert_eq!(
            SntpTimestamp::from_bytes(before_2036).to_bytes(),
            before_2036
        );
        assert_eq!(SntpTimestamp::from_bytes(after_2036).to_bytes(), after_2036);
    }

    #[test]
    fn timestamp_to_datetime_works_correctly() {
        let before_1970 =
            SntpTimestamp::from_bytes([0x82, 0x89, 0x9d, 0xf6, 0x14, 0xf2, 0x58, 0x1a])
                .to_datetime();
        let before_2036 =
            SntpTimestamp::from_bytes([0xc5, 0x02, 0x03, 0x4c, 0x36, 0xbb, 0xa9, 0x8e])
                .to_datetime();
        let after_2036 =
            SntpTimestamp::from_bytes([0x08, 0x1D, 0xD1, 0x80, 0x80, 0x00, 0x00, 0x00])
                .to_datetime();

        assert_eq!(
            before_1970,
            Utc.ymd(1969, 5, 26).and_hms_nano(21, 9, 10, 81_822_878)
        );

        assert_eq!(
            before_2036,
            Utc.ymd(2004, 9, 27).and_hms_nano(3, 11, 8, 213_800_999)
        );

        assert_eq!(
            after_2036,
            Utc.ymd(2040, 6, 1).and_hms_nano(8, 0, 0, 500_000_000)
        );
    }

    #[test]
    fn timestamp_from_datetime_works_correctly() {
        let before_1970 =
            SntpTimestamp::from_datetime(Utc.ymd(1969, 5, 26).and_hms_nano(21, 9, 10, 81_822_878));
        let before_2036 =
            SntpTimestamp::from_datetime(Utc.ymd(2004, 9, 27).and_hms_nano(3, 11, 8, 213_800_999));
        let after_2036 =
            SntpTimestamp::from_datetime(Utc.ymd(2040, 6, 1).and_hms_nano(8, 0, 0, 500_000_000));

        assert_eq!(
            before_1970.to_bytes(),
            [0x82, 0x89, 0x9d, 0xf6, 0x14, 0xf2, 0x58, 0x19]
        );

        assert_eq!(
            before_2036.to_bytes(),
            [0xc5, 0x02, 0x03, 0x4c, 0x36, 0xbb, 0xa9, 0x8a]
        );

        assert_eq!(
            after_2036.to_bytes(),
            [0x08, 0x1D, 0xD1, 0x80, 0x80, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn decoding_a_packet_works() {
        let raw = [
            0x23, 0x02, 0x0a, 0xec, 0x00, 0x00, 0x02, 0x86, 0x00, 0x00, 0x0b, 0x33, 0xcc, 0x7b,
            0x02, 0x48, 0xc5, 0x02, 0x02, 0xac, 0x41, 0x6e, 0x15, 0x87, 0xc5, 0x02, 0x04, 0xec,
            0xee, 0xd3, 0x3c, 0x52, 0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xd8, 0xd7, 0x9d, 0xc5, 0x02,
            0x04, 0xeb, 0xd9, 0xdc, 0xb5, 0x78,
        ];

        let packet = Packet::from_bytes(&raw).unwrap();

        assert_eq!(packet.li, LeapIndicator::NoWarning);
        assert_eq!(packet.mode, Mode::Client);
        assert_eq!(packet.stratum, 2);
        assert_eq!(
            packet.reference_identifier,
            ReferenceIdentifier::IpAddress(IpAddr::from([0xcc, 0x7b, 0x02, 0x48]))
        );

        assert_eq!(
            packet.reference_timestamp,
            SntpTimestamp::from_bytes([0xc5, 0x02, 0x02, 0xac, 0x41, 0x6e, 0x15, 0x87])
        );
        assert_eq!(
            packet.originate_timestamp,
            SntpTimestamp::from_bytes([0xc5, 0x02, 0x04, 0xec, 0xee, 0xd3, 0x3c, 0x52])
        );
        assert_eq!(
            packet.receive_timestamp,
            SntpTimestamp::from_bytes([0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xd8, 0xd7, 0x9d])
        );
        assert_eq!(
            packet.transmit_timestamp,
            SntpTimestamp::from_bytes([0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xdc, 0xb5, 0x78])
        );
    }

    #[test]
    fn decoding_a_packet_with_wrong_version_fails() {
        let raw = [
            0x1a, 0x02, 0x0a, 0xec, 0x00, 0x00, 0x02, 0x86, 0x00, 0x00, 0x0b, 0x33, 0xcc, 0x7b,
            0x02, 0x48, 0xc5, 0x02, 0x02, 0xac, 0x41, 0x6e, 0x15, 0x87, 0xc5, 0x02, 0x04, 0xec,
            0xee, 0xd3, 0x3c, 0x52, 0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xd8, 0xd7, 0x9d, 0xc5, 0x02,
            0x04, 0xeb, 0xd9, 0xdc, 0xb5, 0x78,
        ];

        assert_eq!(
            Packet::from_bytes(&raw).unwrap_err(),
            ProtocolError::InvalidPacketVersion
        );
    }

    #[test]
    fn decoding_a_short_packet_fails() {
        let raw = [
            0x23, 0x02, 0x0a, 0xec, 0x00, 0x00, 0x02, 0x86, 0x00, 0x00, 0x0b, 0x33, 0xcc, 0x7b,
            0x02, 0x48,
        ];

        assert_eq!(
            Packet::from_bytes(&raw).unwrap_err(),
            ProtocolError::PacketIsTooShort
        );
    }

    #[test]
    fn decoding_a_packet_with_illegal_mode_fails() {
        let raw = [
            0x20, 0x02, 0x0a, 0xec, 0x00, 0x00, 0x02, 0x86, 0x00, 0x00, 0x0b, 0x33, 0xcc, 0x7b,
            0x02, 0x48, 0xc5, 0x02, 0x02, 0xac, 0x41, 0x6e, 0x15, 0x87, 0xc5, 0x02, 0x04, 0xec,
            0xee, 0xd3, 0x3c, 0x52, 0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xd8, 0xd7, 0x9d, 0xc5, 0x02,
            0x04, 0xeb, 0xd9, 0xdc, 0xb5, 0x78,
        ];

        assert_eq!(
            Packet::from_bytes(&raw).unwrap_err(),
            ProtocolError::InvalidMode
        );
    }

    #[test]
    fn encoding_a_packet_works() {
        let packet = Packet {
            li: LeapIndicator::NoWarning,
            mode: Mode::Client,
            stratum: 0,
            reference_identifier: ReferenceIdentifier::Empty,
            reference_timestamp: SntpTimestamp::from_bytes([
                0xc5, 0x02, 0x02, 0xac, 0x41, 0x6e, 0x15, 0x87,
            ]),
            originate_timestamp: SntpTimestamp::from_bytes([
                0xc5, 0x02, 0x04, 0xec, 0xee, 0xd3, 0x3c, 0x52,
            ]),
            receive_timestamp: SntpTimestamp::from_bytes([
                0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xd8, 0xd7, 0x9d,
            ]),
            transmit_timestamp: SntpTimestamp::from_bytes([
                0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xdc, 0xb5, 0x78,
            ]),
        };

        assert_eq!(
            packet.to_bytes().to_vec(),
            vec![
                0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xc5, 0x02, 0x02, 0xac, 0x41, 0x6e, 0x15, 0x87, 0xc5, 0x02, 0x04, 0xec,
                0xee, 0xd3, 0x3c, 0x52, 0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xd8, 0xd7, 0x9d, 0xc5, 0x02,
                0x04, 0xeb, 0xd9, 0xdc, 0xb5, 0x78
            ]
        );
    }
    #[test]
    #[should_panic]
    fn encoding_a_packet_with_non_empty_reference_identifier_fails() {
        let packet = Packet {
            li: LeapIndicator::NoWarning,
            mode: Mode::Client,
            stratum: 0,
            reference_identifier: ReferenceIdentifier::ASCII("abcd".into()),
            reference_timestamp: SntpTimestamp::from_bytes([
                0xc5, 0x02, 0x02, 0xac, 0x41, 0x6e, 0x15, 0x87,
            ]),
            originate_timestamp: SntpTimestamp::from_bytes([
                0xc5, 0x02, 0x04, 0xec, 0xee, 0xd3, 0x3c, 0x52,
            ]),
            receive_timestamp: SntpTimestamp::from_bytes([
                0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xd8, 0xd7, 0x9d,
            ]),
            transmit_timestamp: SntpTimestamp::from_bytes([
                0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xdc, 0xb5, 0x78,
            ]),
        };

        let _ = packet.to_bytes();
    }

    #[test]
    fn decoding_ascii_reference_identifier_works() {
        let raw = [
            0x23, 0x01, 0x0a, 0xec, 0x00, 0x00, 0x02, 0x86, 0x00, 0x00, 0x0b, 0x33, 0x4c, 0x4f,
            0x43, 0x4c, 0xc5, 0x02, 0x02, 0xac, 0x41, 0x6e, 0x15, 0x87, 0xc5, 0x02, 0x04, 0xec,
            0xee, 0xd3, 0x3c, 0x52, 0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xd8, 0xd7, 0x9d, 0xc5, 0x02,
            0x04, 0xeb, 0xd9, 0xdc, 0xb5, 0x78,
        ];

        let packet = Packet::from_bytes(&raw).unwrap();

        assert_eq!(
            packet.reference_identifier,
            ReferenceIdentifier::ASCII("LOCL".into())
        );
    }

    #[test]
    fn decoding_short_ascii_reference_identifier_works() {
        let raw = [
            0x23, 0x01, 0x0a, 0xec, 0x00, 0x00, 0x02, 0x86, 0x00, 0x00, 0x0b, 0x33, 0x47, 0x50,
            0x53, 0x00, 0xc5, 0x02, 0x02, 0xac, 0x41, 0x6e, 0x15, 0x87, 0xc5, 0x02, 0x04, 0xec,
            0xee, 0xd3, 0x3c, 0x52, 0xc5, 0x02, 0x04, 0xeb, 0xd9, 0xd8, 0xd7, 0x9d, 0xc5, 0x02,
            0x04, 0xeb, 0xd9, 0xdc, 0xb5, 0x78,
        ];

        let packet = Packet::from_bytes(&raw).unwrap();

        assert_eq!(
            packet.reference_identifier,
            ReferenceIdentifier::ASCII("GPS".into())
        );
    }
}
