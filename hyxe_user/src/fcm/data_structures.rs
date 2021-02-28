use serde::{Serialize, Deserialize};
use hyxe_crypt::fcm::fcm_ratchet::FcmAliceToBobTransfer;
use hyxe_crypt::endpoint_crypto_container::KemTransferStatus;
use zerocopy::{AsBytes, FromBytes, Unaligned, U64, U32, LayoutVerified};
use bytes::BufMut;
use byteorder::BigEndian;
use std::fmt::Formatter;
use hyxe_fs::hyxe_crypt::prelude::EzBuffer;
use crate::fcm::kem::FcmPostRegister;

pub struct FcmPacket {
    header: Vec<u8>,
    payload: Vec<u8>
}

impl std::fmt::Debug for FcmPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?} | payload len: {}", self.header(), self.payload.len())
    }
}

impl FcmPacket {
    pub fn from_raw_fcm_packet(packet: &RawFcmPacket) -> Option<Self> {
        let mut raw = base64::decode(packet.inner.as_bytes()).ok()?;
        if raw.len() < FCM_HEADER_BYTES {
            log::warn!("[FCM] packet too small");
            return None;
        }

        let header = raw.split_to(FCM_HEADER_BYTES);
        // verify layout
        let _ = FcmHeader::try_from(header.as_slice())?;

        Some(Self { header, payload: raw  })
    }

    pub fn header(&self) -> LayoutVerified<&[u8], FcmHeader> {
        LayoutVerified::<&[u8], FcmHeader>::new(self.header.as_slice()).unwrap()
    }

    /// returns (header, payload)
    pub fn split(self) -> (Vec<u8>, Vec<u8>) {
        (self.header, self.payload)
    }
}

pub const FCM_HEADER_BYTES: usize = std::mem::size_of::<FcmHeader>();
///
#[derive(Debug, AsBytes, FromBytes, Unaligned)]
#[repr(C)]
pub struct FcmHeader {
    /// the hdp header + payload that goes from the client to the central server
    pub session_cid: U64<BigEndian>,
    pub target_cid: U64<BigEndian>,
    pub group_id: U64<BigEndian>,
    pub ticket: U64<BigEndian>,
    pub object_id: U32<BigEndian>,
    pub ratchet_version: U32<BigEndian>
}

impl FcmHeader {
    pub fn inscribe_into<B: BufMut>(&self, packet: &mut B) {
        packet.put_u64(self.session_cid.get());
        packet.put_u64(self.target_cid.get());
        packet.put_u64(self.group_id.get());
        packet.put_u64(self.ticket.get());
        packet.put_u32(self.object_id.get());
        packet.put_u32(self.ratchet_version.get());
    }

    pub fn try_from(input: &[u8]) -> Option<LayoutVerified<&[u8], FcmHeader>> {
        LayoutVerified::new(input)
    }
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug)]
pub struct FcmTicket {
    #[serde(with = "string")]
    source_cid: u64,
    #[serde(with = "string")]
    target_cid: u64,
    #[serde(with = "string")]
    ticket: u64
}

impl FcmTicket {
    pub fn new(source_cid: u64, target_cid: u64, ticket: u64) -> Self {
        Self { source_cid, target_cid, ticket }
    }
}

/// This always gets encrypted
#[derive(Serialize, Deserialize)]
pub enum FCMPayloadType<'a> {
    GroupHeader { #[serde(borrow)] alice_to_bob_transfer: Option<FcmAliceToBobTransfer<'a>>, #[serde(with = "serde_bytes")] message: &'a [u8] },
    GroupHeaderAck { bob_to_alice_transfer: KemTransferStatus },
    Truncate { truncate_vers: u32 },
    PeerPostRegister { transfer: FcmPostRegister, username: String } // the rest of the info will exist in the FCM header
}

#[derive(Serialize, Deserialize)]
pub struct RawFcmPacket {
    pub(crate) inner: String
}

impl<T: Into<String>> From<T> for RawFcmPacket {
    fn from(val: T) -> Self {
        Self { inner: val.into() }
    }
}

pub mod string {
    use std::fmt::Display;
    use serde::{Serializer, Deserialize, Deserializer};
    use std::str::FromStr;

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where T: Display,
              S: Serializer
    {
        serializer.collect_str(value)
    }

    pub fn deserialize<'de, D, T>(value: D) -> Result<T, D::Error> where D: Deserializer<'de>, T: FromStr {
        T::from_str(&String::deserialize(value).map_err(|_| serde::de::Error::custom("Deser err"))?).map_err(|_| serde::de::Error::custom("Deser err"))
    }
}


pub mod base64_string {
    use serde::{Serializer, Deserializer, Deserialize};

    pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where T: AsRef<[u8]>,
              S: Serializer
    {
        serializer.collect_str(&base64::encode(value))
    }

    pub fn deserialize<'de, D>(value: D) -> Result<Vec<u8>, D::Error> where D: Deserializer<'de> {
        base64::decode(String::deserialize(value).map_err(|_| serde::de::Error::custom("Deser err"))?).map_err(|_| serde::de::Error::custom("Deser err"))
    }
}
