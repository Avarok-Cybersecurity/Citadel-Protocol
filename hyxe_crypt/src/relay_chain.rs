use linked_hash_map::LinkedHashMap;
use bytes::BytesMut;
use crate::net::crypt_splitter::calculate_aes_gcm_output_length;
use crate::hyper_ratchet::Ratchet;

/// Suppose we want to communicate from A -> B -> C -> D
/// Let definition "KA" => ordinary session key exchange.
///
/// 0. Establish KA(A->B) => KA_0
/// 1. Establish KA(B->C) => KA_1
/// 2. Establish KA(C->D) => KA_2
///
/// Following steps 0 through 2, we setup an ordinary route. However, we want only D to be able to
/// decrypt the packet from A. Thus, after steps 0-2, step 3 is:
///
/// 3. KA(A->D) => KA_S by proxying packet, using ordinary KA_0 -> KA_1 -> KA_2
///
/// Then, if A wants to communicate to D, first A uses KA_S to encrypt the plaintext, P, to obtain X.
/// A then places X inside a new packet, impersonating C as if C were to send a normal packet to D, obtaining
/// Packet(C->D). Next, A places Packet(C->D) as an encrypted payload of similar Packet(B->C). Next, A
/// places Packet(B->C) inside Packet(A->B). This way, A send the packet to B, and B maps Packet(A->B) into
/// the payload of Packet(B->C). Then, B relays the packet to C, where C obtains Packet(C->D). Then, C
/// relays the packet to D, where D obtains X. D then uses KA_S to map X to P to obtain the plaintext.
///
/// This process requires the A and D contain the symmetric keys between all nodes. These symmetric keys can
/// be distributed to both ends using ***KA_S***, since we want to keep the intermediary symmetric keys free from the nodes
/// in the middle as much as possible
pub struct CryptoRelayChain<R: Ratchet> {
    /// NOTE: KA_S should be the first item, then KA_2, KA_1, then KA_0 the last
    pub links: LinkedHashMap<u64, PeerSessionCrypto<R>>,
    /// The list of cids in the order in which the onion packets are created
    pub target_cid_list: Option<Vec<u64>>
}

impl<R: Ratchet> CryptoRelayChain<R> {
    /// Creates a new RelayChain
    pub fn new(relay_len: usize) -> Option<Self> {
        if relay_len < 2 {
            None
        } else {
            Some(Self { links: LinkedHashMap::with_capacity(relay_len), target_cid_list: None })
        }
    }

    /// Once all the links have been loaded, this should be called to generate a list of target CIDS
    pub fn on_finish(&mut self) -> Option<()> {
        // The first needs to be zero, as it's the packet going from Packet(C->D) -> P
        let mut target_cid_list = Vec::with_capacity(self.links.len());
        target_cid_list.push(0);
        // then, the packet Packet(C->D) is also zero since this is the last hop
        target_cid_list.push(0);
        let keys = self.links.keys();
        // then, the packet Packet(B->C) should have the target_cid of D
        // target_cid_list.push(*keys.next()?);
        // then, the packet Packet(A->B) should have the target_cid of C
        // target_cid_list.push(*keys.next()?);
        // At this point, we have itered through 2/4 of the entries. We want to not input the last and second to last item
        // in general, we iterate through the entire list minus the last two items (since we don't need the target CID of a or B
        // , placing it into the vec
        keys.take(self.links.len() - 2).for_each(|key| target_cid_list.push(*key));
        debug_assert_eq!(target_cid_list.len(), self.links.len());
        self.target_cid_list = Some(target_cid_list);
        Some(())
    }

    /// Must be inserted in order
    pub fn push(&mut self, cid: u64, container: PeerSessionCrypto<R>) -> bool {
        self.links.insert(cid, container).is_none()
    }

    /// Encrypts a singular unit into an onion packet. The innermost encryption (zeroth pass) uses the furthermost
    /// endpoint's encryption, followed by each additional endpoint between each hop in the order of increasing
    /// proximity
    pub fn encrypt<T: AsRef<[u8]>>(&self, input: T, nonce_version: usize, header_len: usize, header_inscriber: impl Fn(&R, u64, &mut BytesMut)) -> Option<BytesMut> {
        // the zeroth entry must be applied first. Its target CID is zero
        // the last entry needs to have a target_cid equal to C's CID
        // thus, we need to zip a vector to this iter that has the target cids
        let input = input.as_ref();
        let target_cids = self.target_cid_list.as_ref()?;
        self.links.iter().zip(target_cids.iter()).enumerate().try_fold(BytesMut::new(),
        |mut acc, (idx, ((_cid, container), target_cid))| {
            let hyper_ratchet = container.get_hyper_ratchet(None)?;
            let (msg_pqc, msg_drill) = hyper_ratchet.message_pqc_drill(None);
            log::trace!("At IDX {} using endpoint container {}. Target CID: {}", idx, _cid, target_cid);
            if idx != 0 {
                // we need to take the previous packet and make it the payload of a new packet
                let mut outer_packet = BytesMut::with_capacity(header_len + calculate_aes_gcm_output_length(acc.len()));
                (header_inscriber)(hyper_ratchet, *target_cid, &mut outer_packet);
                // now, place the payload encrypted
                let _len = msg_drill.aes_gcm_encrypt_into(nonce_version, msg_pqc, acc, &mut outer_packet).ok()?;
                Some(outer_packet)
            } else {
                (header_inscriber)(hyper_ratchet, *target_cid, &mut acc);
                // this is the first. Place the input inside the packet encrypted
                let _len = msg_drill.aes_gcm_encrypt_into(nonce_version, msg_pqc, input, &mut acc).ok()?;
                Some(acc)
            }
        })
    }

    /// Borrow the drill and pqc
    pub fn borrow_drill_and_pqc(&self, cid: u64, drill_version: Option<u32>) -> Option<&R> {
        self.links.get(&cid)
            .and_then(|res| res.get_hyper_ratchet(drill_version))
    }

}

#[cfg(debug_assertions)]
use std::iter::FromIterator;
use crate::endpoint_crypto_container::PeerSessionCrypto;

#[cfg(debug_assertions)]
impl<R: Ratchet> FromIterator<PeerSessionCrypto<R>> for CryptoRelayChain<R> {
    fn from_iter<T: IntoIterator<Item=PeerSessionCrypto<R>>>(iter: T) -> Self {
        let iter = iter.into_iter();
        let mut this = CryptoRelayChain { links: LinkedHashMap::new(), target_cid_list: None };
        for val in iter {
            if let Some(_) = this.links.insert(val.toolset.cid, val) {

            }
        }

        this.on_finish().unwrap();
        this
    }
}