pub(crate) mod do_connect {
    use byteorder::{BigEndian, ByteOrder};
    use secstr::SecVec;
    use zerocopy::LayoutVerified;

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use hyxe_crypt::drill::Drill;
    use hyxe_crypt::prelude::SecurityLevel;
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::error::NetworkError;
    use crate::hdp::hdp_packet::HdpHeader;
    use crate::hdp::peer::peer_layer::MailboxTransfer;
    use crate::hdp::state_container::StateContainerInner;
    use crate::inner_arg::{ExpectedInnerTargetMut, InnerParameterMut};

    /// Bob receives this (presumably the server). Returns the NAT ports
    pub(crate) fn validate_stage0_packet(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(Drill, PostQuantumContainer)> {
        let pk_len = header.context_info.get() as usize;
        if payload.len() != pk_len {
            log::error!("Bad payload len on stage 0 connect packet");
            return None;
        }

        let drill = cnac.get_drill(Some(header.drill_version.get()))?;
        let algorithm = header.algorithm;

        //let sec0 = drill.get_ultra()[0][0];
        let sec1 = drill.get_ultra()[0][1];
        let sec2 = drill.get_high()[0][2];

        let security_level = header.security_level;
        if security_level > SecurityLevel::DIVINE.value() {
            return None;
        }

        let security_level = SecurityLevel::for_value(security_level as usize).unwrap();

        if header.group.get() != sec1 || header.wave_id.get() != sec2 {
            None
        } else {
            let alice_public_key_encrypted = payload;
            let alice_public_key = drill.decrypt_to_vec(alice_public_key_encrypted, 0, security_level).unwrap();
            //log::info!("PUBLIC KEY(len: {}): {:?}", alice_public_key.len(), &alice_public_key);

            if alice_public_key.len() != 0 {
                if let Ok(pqc_bob) = PostQuantumContainer::new_bob(algorithm, &alice_public_key) {
                    Some((drill, pqc_bob))
                } else {
                    log::error!("Unable to generate Bob PQC container");
                    None
                }
            } else {
                log::error!("Received an empty public key. Dropping packet");
                None
            }
        }
    }

    /// Alice receives this (presumably the client). She receives a nonce from Bob
    pub(crate) fn validate_stage1_packet(drill: &Drill, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<([u8; AES_GCM_NONCE_LEN_BYTES], Vec<u8>)> {
        if payload.len() <= AES_GCM_NONCE_LEN_BYTES {
            return None;
        }

        let security_level = header.security_level;
        if security_level > SecurityLevel::DIVINE.value() {
            return None;
        }

        let sec0 = drill.get_ultra()[0][3];
        let sec1 = drill.get_high()[0][4];

        if header.group.get() != sec0 || header.wave_id.get() != sec1 {
            None
        } else {
            // Now, get the encrypted nonce and decrypt it
            let (encrypted_nonce, encrypted_ciphertext) = payload.split_at(AES_GCM_NONCE_LEN_BYTES);
            let ciphertext_len = header.context_info.get() as usize;

            if encrypted_ciphertext.len() != ciphertext_len {
                return None;
            }

            let security_level = SecurityLevel::for_value(security_level as usize).unwrap();

            let decrypted_nonce: Vec<u8> = drill.decrypt_to_vec(encrypted_nonce, 0, security_level).unwrap();

            let mut decrypted_nonce_ret: [u8; AES_GCM_NONCE_LEN_BYTES] = [0u8; AES_GCM_NONCE_LEN_BYTES];
            for idx in 0..AES_GCM_NONCE_LEN_BYTES {
                decrypted_nonce_ret[idx] = decrypted_nonce[idx];
            }

            let decrypted_ciphertext = drill.decrypt_to_vec(encrypted_ciphertext, 0, security_level).unwrap();

            Some((decrypted_nonce_ret, decrypted_ciphertext))
        }
    }

    /// Here, Bob receives a payload of the encrypted username + password. We must verify the login data is valid
    pub(crate) fn validate_stage2_packet(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Result<(), NetworkError> {
        // Now, validate the username and password. The payload is already decrypted
        let split_idx = header.context_info.get() as usize;
        if split_idx > payload.len() {
            Err(NetworkError::InvalidPacket("Packet has an oob username/password split index. Dropping"))
        } else {
            let (username, password) = payload.split_at(split_idx);
            cnac.validate_credentials(username, SecVec::new(Vec::from(password))).map_err(|err| NetworkError::Generic(err.to_string()))?;
            log::info!("Success validating credentials!");
            Ok(())
        }
    }

    pub(crate) fn validate_final_status_packet<K: ExpectedInnerTargetMut<StateContainerInner>>(state_container: &mut InnerParameterMut<K, StateContainerInner>, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Result<Option<(Drill, Vec<u8>, Option<MailboxTransfer>, Vec<u64>)>, ()> {
        let drill = state_container.connect_register_drill.as_ref().ok_or(())?;
        let msg_len = header.context_info.get() as usize;
        let mailbox_len = header.group.get() as usize;

        let (msg, mailbox_transfer_and_peers_bytes) = payload.split_at(msg_len);
        let (mailbox_transfer_bytes, peers_bytes) = mailbox_transfer_and_peers_bytes.split_at(mailbox_len);

        let mailbox = if mailbox_transfer_bytes.len() != 0 {
            MailboxTransfer::deserialize_from(mailbox_transfer_bytes)
        } else {
            None
        };

        if peers_bytes.len() % 8 != 0 {
            log::error!("Final status packet has invalid peer_bytes length");
            return Err(());
        }

        let peers = peers_bytes.chunks_exact(8).map(|vals| BigEndian::read_u64(vals)).collect::<Vec<u64>>();

        Ok(Some((drill.clone(), Vec::from(msg), mailbox, peers)))
    }
}

pub(crate) mod keep_alive {
    use bytes::{Bytes, BytesMut};
    use zerocopy::LayoutVerified;

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::drill::Drill;
    use hyxe_user::prelude::ClientNetworkAccount;

    use crate::hdp::hdp_packet::HdpHeader;

    /// Returns Ok(false) if expired.
                /// Returns Ok(true) if valid
                /// Return Err(_) if getting the drill failed or the security params were false
    pub(crate) fn validate_keep_alive<'a, 'b: 'a>(cnac: &ClientNetworkAccount, pqc: &PostQuantumContainer, header: &'b Bytes, payload: BytesMut) -> Option<(LayoutVerified<&'a [u8], HdpHeader>, Bytes, Drill)> {
        super::aead::validate(cnac, pqc, header, payload)
    }
}

pub(crate) mod group {
    use std::ops::RangeInclusive;

    use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
    use bytes::{Buf, Bytes, BytesMut};
    use zerocopy::LayoutVerified;

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::net::crypt_splitter::{calculate_nonce_version, GROUP_RECEIVER_INSCRIBE_LEN};
    use hyxe_crypt::net::crypt_splitter::GroupReceiverConfig;
    use hyxe_crypt::prelude::Drill;
    use hyxe_crypt::sec_bytes::SecBuffer;

    //use crate::hdp::file_transfer::MAX_GROUP_PLAINTEXT_LEN;
    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::error::NetworkError;
    use crate::hdp::hdp_packet::{HdpHeader, packet_sizes};
    use crate::hdp::hdp_packet::packet_sizes::GROUP_HEADER_ACK_LEN;
    use crate::hdp::state_container::VirtualTargetType;

    /// First-pass validation. Ensures header integrity through AAD-services in AES-GCM
    pub(crate) fn validate<'a, 'b: 'a>(drill: &Drill, pqc: &PostQuantumContainer, header: &'b [u8], mut payload: BytesMut) -> Option<Bytes> {
        //let bytes = &header[..];
        //let header = LayoutVerified::new(bytes)? as LayoutVerified<&[u8], HdpHeader>;
        drill.validate_packet_in_place_split(pqc, header, &mut payload).ok()?;
        Some(payload.freeze())
    }

    pub(crate) fn validate_header(_header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(GroupReceiverConfig, VirtualTargetType)> {
        if payload.len() < GROUP_HEADER_PAYLOAD_LEN {
            None
        } else {
            let start_idx = 0;
            let end_idx = start_idx + GROUP_RECEIVER_INSCRIBE_LEN;
            let group_receiver_config = GroupReceiverConfig::try_from_bytes(&payload[start_idx..end_idx])?;
            if group_receiver_config.plaintext_length > hyxe_user::prelude::MAX_BYTES_PER_GROUP {
                log::error!("The provided GroupReceiverConfiguration contains an oversized allocation request. Dropping ...");
                None
            } else {
                // Now, get the virtual target
                let target = VirtualTargetType::deserialize_from(&payload[end_idx..])?;
                Some((group_receiver_config, target))
            }
        }
    }

    /// Returns None if the packet is invalid. Returns Some(is_ready_to_accept) if the packet is valid
    pub(crate) fn validate_header_ack(payload: &[u8]) -> Option<(bool, RangeInclusive<u32>, Option<Vec<u8>>)> {
        if payload.len() < GROUP_HEADER_ACK_LEN - HDP_HEADER_BYTE_LEN {
            log::error!("Invalid HEADER ACK payload len");
            return None;
        }

        let mut reader = payload.reader();
        let ready_to_accept = reader.read_u8().ok()? == 1;
        let window_start = reader.read_u32::<BigEndian>().ok()?;
        let window_end = reader.read_u32::<BigEndian>().ok()?;

        // up to this point, all the previous bytes are assured.
        // note: the reader's into_inner returns a pointer that has moved w.r.t. the original payload ptr
        let remaining_payload = reader.into_inner();
        let message_opt = if remaining_payload.len() != 0 {
            Some(remaining_payload.to_vec())
        } else {
            None
        };

        Some((ready_to_accept, window_start..=window_end, message_opt))
    }

    pub(crate) fn validate_window_tail(header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<RangeInclusive<u32>> {
        if payload.len() != packet_sizes::GROUP_WINDOW_TAIL_LEN - HDP_HEADER_BYTE_LEN {
            None
        } else {
            let start = header.wave_id.get();
            let end = BigEndian::read_u32(payload);
            Some(start..=end)
        }
    }

    pub(crate) fn validate_wave_do_retransmission(payload: &[u8]) -> Result<(), NetworkError> {
        // The payload must be greater than 4 bytes
        // but the protocol does not send an unnecessary WAVE_DO_RETRANSMISSION
        let payload_len = payload.len();
        if payload_len < 4 {
            Err(NetworkError::InvalidPacket("Bad payload size"))
        } else {
            if payload_len % 4 != 0 {
                Err(NetworkError::InvalidPacket("The payload of the packet must be groups of 2 16-bit values (4-byte chunks)"))
            } else {
                Ok(())
            }
        }
    }

    /// Will return Ok(_) if valid. Will return Ok(Some(_)) if the window is complete, or Ok(None) if just a simple ack
    pub(crate) fn validate_wave_ack(payload: &[u8]) -> Result<Option<RangeInclusive<u32>>, NetworkError> {
        let payload_len = payload.len();
        // The packet is either 8 (normal) or 4 (dummy security parameter)
        if payload_len != 4 && payload_len != 8 {
            Err(NetworkError::InvalidPacket("Bad payload size"))
        } else {
            if payload_len != 8 {
                Ok(None)
            } else {
                let start = BigEndian::read_u32(&payload[..4]);
                let end = BigEndian::read_u32(&payload[4..8]);
                Ok(Some(start..=end))
            }
        }
    }
}

pub(crate) mod do_register {
    use std::net::SocketAddr;

    use bstr::ByteSlice;
    use secstr::SecVec;
    use zerocopy::LayoutVerified;

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use hyxe_user::network_account::NetworkAccount;

    use crate::hdp::hdp_packet::HdpHeader;
    use crate::proposed_credentials::ProposedCredentials;

    pub(crate) fn validate_stage2(_header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<[u8; AES_GCM_NONCE_LEN_BYTES]> {
        if payload.len() != AES_GCM_NONCE_LEN_BYTES {
            log::error!("Stage 2 payload improperly sized");
            return None;
        }

        let mut nonce: [u8; AES_GCM_NONCE_LEN_BYTES] = [0u8; AES_GCM_NONCE_LEN_BYTES];
        for idx in 0..AES_GCM_NONCE_LEN_BYTES {
            nonce[idx] = payload[idx];
        }

        Some(nonce)
    }

    pub(crate) fn validate_stage3(_header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> bool {
        payload.len() == 0
    }

    /// Returns the decrypted username, password, and full name
    pub(crate) fn validate_stage4(header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8], nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], post_quantum: &PostQuantumContainer, peer_addr: SocketAddr) -> Option<(ProposedCredentials, NetworkAccount)> {
        let username_len = header.context_info.get() as usize;
        let password_len = header.group.get() as usize;
        let fullname_len = header.wave_id.get() as usize;

        if let Ok(plaintext_bytes) = post_quantum.decrypt(payload, nonce) {
            let (username, plaintext_bytes) = plaintext_bytes.split_at(username_len);
            debug_assert_eq!(username.len(), username_len);
            let (password, full_name) = plaintext_bytes.split_at(password_len);
            if full_name.len() != fullname_len {
                log::error!("The length of the payload was invalid. Invalid stage 4 packet");
                return None;
            }

            let full_name = String::from_utf8(full_name.to_vec()).ok()?;
            let username = String::from_utf8(username.to_vec()).ok()?;

            let (full_name, username) = (full_name.trim(), username.trim());
            let password = password.trim();

            let proposed_credentials = ProposedCredentials::new_from_hashed(full_name, username, SecVec::new(password.to_vec()), nonce.clone());
            let adjacent_nid = header.session_cid.get();
            let adjacent_nac = NetworkAccount::new_from_recent_connection(adjacent_nid, peer_addr);
            Some((proposed_credentials, adjacent_nac))
        } else {
            log::error!("Error using AES-GCM decryption on the stage 4 packet");
            None
        }
    }

    /// Returns the decrypted Toolset text, as well as the welcome message
    pub(crate) fn validate_success(header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8], nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], post_quantum: &PostQuantumContainer) -> Option<(Vec<u8>, Vec<u8>)> {
        let cnac_ciphertext_len = header.context_info.get() as usize;
        log::info!("CNAC ciphertext len: {} | payload len: {}", cnac_ciphertext_len, payload.len());
        if payload.len() < cnac_ciphertext_len {
            log::error!("invalid payload len for the success packet");
            return None;
        }

        let (cnac_ciphertext, welcome_message) = payload.split_at(cnac_ciphertext_len);
        debug_assert_eq!(cnac_ciphertext.len(), cnac_ciphertext_len);
        if let Ok(cnac_plaintext) = post_quantum.decrypt(cnac_ciphertext, nonce) {
            Some((cnac_plaintext, welcome_message.to_vec()))
        } else {
            log::error!("Error using AES-GCM decryption on the success packet!");
            None
        }
    }

    /// Returns the error message
    pub(crate) fn validate_failure(_header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<Vec<u8>> {
        Some(payload.to_vec())
    }
}

pub(crate) mod do_disconnect {
    use zerocopy::LayoutVerified;

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use hyxe_crypt::drill::Drill;
    use hyxe_crypt::drill::E_OF_X_START_INDEX;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::error::NetworkError;
    use crate::hdp::hdp_packet::{HdpHeader, packet_sizes};
    use crate::hdp::hdp_server::Ticket;
    use crate::hdp::state_container::VirtualConnectionType;

    /// Returns the identifier and target cid
    pub(crate) fn validate_stage0(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(VirtualConnectionType, Ticket, Drill)> {
        if payload.len() == 0 {
            log::error!("The payload of the packet has an invalid size. Dropping");
            return None;
        }

        let security_level = header.security_level;
        if security_level > SecurityLevel::DIVINE.value() {
            log::error!("Invalid security level of packet. Dropping");
            return None;
        }

        let security_level = SecurityLevel::for_value(security_level as usize).unwrap();

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][0];
            let sec1 = drill.get_high()[0][1];

            if sec0 != header.group.get() || sec1 != header.wave_id.get() {
                log::error!("Invalid security parameters on disconnect packet");
                return None;
            }

            let ticket = Ticket(header.context_info.get());
            let data = drill.decrypt_to_vec(payload, 0, security_level).unwrap();
            let virt_cxn_type = VirtualConnectionType::deserialize_from(data)?;
            Some((virt_cxn_type, ticket, drill))
        } else {
            log::error!("Drill missing for stage 0 do_disconnect packet. Dropping");
            None
        }
    }

    /// Returns the identifier and target cid
    pub(crate) fn validate_stage1(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<([u8; AES_GCM_NONCE_LEN_BYTES], Ticket, Drill)> {
        if payload.len() != packet_sizes::disconnect::STAGE1 - HDP_HEADER_BYTE_LEN {
            log::error!("The payload of the packet has an invalid size. Dropping");
            return None;
        }

        let security_level = header.security_level;
        if security_level > SecurityLevel::DIVINE.value() {
            log::error!("Invalid security level of packet. Dropping");
            return None;
        }

        let security_level = SecurityLevel::for_value(security_level as usize).unwrap();

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][2];
            let sec1 = drill.get_high()[0][3];

            if sec0 != header.group.get() || sec1 != header.wave_id.get() {
                log::error!("Invalid security parameters on disconnect packet");
                return None;
            }

            let ticket = Ticket(header.context_info.get());
            let nonce_decrypted = drill.decrypt_to_vec(payload, 0, security_level).unwrap();
            let mut nonce: [u8; AES_GCM_NONCE_LEN_BYTES] = [0u8; AES_GCM_NONCE_LEN_BYTES];
            for x in 0..AES_GCM_NONCE_LEN_BYTES {
                nonce[x] = nonce_decrypted[x];
            }

            Some((nonce, ticket, drill))
        } else {
            log::error!("Drill missing for stage 1 do_disconnect packet. Dropping");
            None
        }
    }

    pub(crate) fn validate_stage2(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], post_quantum: &PostQuantumContainer, payload: &[u8]) -> Option<(Drill, Ticket)> {
        if payload.len() != packet_sizes::disconnect::STAGE2 - HDP_HEADER_BYTE_LEN {
            log::error!("The payload of the packet has an invalid size. Dropping");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][4];
            let sec1 = drill.get_high()[0][5];

            if sec0 != header.group.get() || sec1 != header.wave_id.get() {
                log::error!("Invalid security parameters on disconnect packet");
                return None;
            }

            if let Ok(decrypted_low_subdrill) = drill.aes_gcm_decrypt_custom_nonce(nonce, post_quantum, &payload) {
                let port_range = drill.get_multiport_width();
                let low_subdrill_real = drill.get_low();
                let mut idx = 0;
                for x in 0..E_OF_X_START_INDEX {
                    for y in 0..port_range {
                        if low_subdrill_real[x][y] != decrypted_low_subdrill[idx] {
                            log::error!("Low subdrills did not match. Dropping");
                            return None;
                        }
                        idx += 1;
                    }
                }

                let ticket = Ticket(header.context_info.get());

                Some((drill, ticket))
            } else {
                log::error!("Invalid stage 2 packet payload");
                None
            }
        } else {
            log::error!("Drill missing for stage 2 do_disconnect packet. Dropping");
            None
        }
    }

    pub(crate) fn validate_final_packet(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Result<(Option<Vec<u8>>, Ticket), NetworkError> {
        let security_level = header.security_level;
        if security_level > SecurityLevel::DIVINE.value() {
            log::error!("Invalid security level of packet. Dropping");
            return Err(NetworkError::InvalidPacket("Invalid security level"));
        }

        let security_level = SecurityLevel::for_value(security_level as usize).unwrap();

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][6];
            let sec1 = drill.get_high()[0][7];

            if sec0 != header.group.get() || sec1 != header.wave_id.get() {
                log::error!("Invalid security parameters on disconnect packet");
                return Err(NetworkError::InvalidPacket("Bad security parameters"));
            }


            let ticket = Ticket(header.context_info.get());
            if payload.len() != 0 {
                let message = drill.decrypt_to_vec(payload, 0, security_level).unwrap();
                Ok((Some(message), ticket))
            } else {
                Ok((None, ticket))
            }
        } else {
            log::error!("Drill missing for stage FINAL do_disconnect packet. Dropping");
            Err(NetworkError::InvalidPacket("CNAC not found for cid provided by packet"))
        }
    }
}

pub(crate) mod do_drill_update {
    use zerocopy::LayoutVerified;

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use hyxe_crypt::drill::Drill;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_crypt::drill_update::DrillUpdateObject;
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags, packet_sizes};

    pub(crate) fn validate_stage0(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<Drill> {
        if payload.len() != packet_sizes::do_drill_update::STAGE0 - HDP_HEADER_BYTE_LEN {
            log::error!("Invalid stage 0 payload len (expected: 0. Actual: {})\n{:?}", payload.len(), header);
            let eq = header.bytes() == payload;
            log::error!("Equal: {}", eq);
            log::error!("{:?}\n\n{:?}", header.bytes(), payload);
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][0];
            let sec1 = drill.get_ultra()[0][1];
            let sec2 = drill.get_high()[0][2];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Invalid stage 0 security parameters");
                None
            } else {
                Some(drill)
            }
        } else {
            log::error!("Unable to obtain drill for stage 0 packet");
            None
        }
    }

    pub(crate) fn validate_stage1(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<([u8; AES_GCM_NONCE_LEN_BYTES], Drill)> {
        if payload.len() != packet_sizes::do_drill_update::STAGE1 - HDP_HEADER_BYTE_LEN {
            log::error!("Invalid stage 1 payload len");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][3];
            let sec1 = drill.get_ultra()[0][4];
            let sec2 = drill.get_high()[0][5];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Invalid stage 1 security parameters");
                None
            } else {
                let nonce_decrypted = drill.decrypt_to_vec(payload, 0, SecurityLevel::LOW).unwrap();
                let mut nonce: [u8; AES_GCM_NONCE_LEN_BYTES] = [0u8; AES_GCM_NONCE_LEN_BYTES];
                for x in 0..AES_GCM_NONCE_LEN_BYTES {
                    nonce[x] = nonce_decrypted[x];
                }
                Some((nonce, drill))
            }
        } else {
            log::error!("Unable to obtain drill for stage 1 packet");
            None
        }
    }

    pub(crate) fn validate_stage2(cnac: &ClientNetworkAccount, post_quantum: &PostQuantumContainer, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<Drill> {
        if payload.len() <= HDP_HEADER_BYTE_LEN {
            log::error!("Invalid stage 2 payload len");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][6];
            let sec1 = drill.get_ultra()[0][7];
            let sec2 = drill.get_high()[0][8];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Invalid stage 1 security parameters");
                None
            } else {
                if let Ok(decrypted_dou) = drill.aes_gcm_decrypt_custom_nonce(nonce, post_quantum, payload) {
                    if let Ok(dou_deserialized) = DrillUpdateObject::deserialize_from_vector(&decrypted_dou) {
                        if dou_deserialized.drill_version.wrapping_sub(1) != drill.get_version() {
                            log::error!("The inbound DOU is not one version ahead of the used drill");
                            return None;
                        }

                        if let Some((_dou, next_drill)) = dou_deserialized.compute_next_recursion(&drill, true) {
                            Some(next_drill)
                        } else {
                            log::error!("Unable to compute next recursion between the drill and its dou");
                            None
                        }
                    } else {
                        log::error!("Unable to deserialize inbound DrillUpdateObject");
                        None
                    }
                } else {
                    log::error!("Error decrypting Drill Update Object");
                    None
                }
            }
        } else {
            log::error!("Unable to obtain drill for stage 1 packet");
            None
        }
    }

    pub(crate) fn validate_stage3(new_drill: &Drill, post_quantum: &PostQuantumContainer, expected_nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> bool {
        if payload.len() != packet_sizes::do_drill_update::STAGE3 - HDP_HEADER_BYTE_LEN {
            log::error!("Invalid stage 3 payload len");
            return false;
        }

        if header.security_level > SecurityLevel::DIVINE.value() {
            log::error!("Invalid");
            return false;
        }

        let security_level = SecurityLevel::for_value(header.security_level as usize).unwrap();

        let sec0 = new_drill.get_ultra()[0][9];
        let sec1 = new_drill.get_ultra()[0][10];
        let sec2 = new_drill.get_high()[0][11];

        if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
            log::error!("Invalid security parameters");
            false
        } else {
            if let Ok(nonce_still_needs_decryption) = new_drill.aes_gcm_decrypt_custom_nonce(expected_nonce, post_quantum, payload) {
                let nonce_fully_decrypted = new_drill.decrypt_to_vec(nonce_still_needs_decryption.as_ref(), 0, security_level).unwrap();
                //log::info!("EXPECTED NONCE: {:?}\nRECV NONCE: {:?}", &nonce_fully_decrypted, expected_nonce);
                nonce_fully_decrypted.as_ref() as &[u8] == expected_nonce as &[u8]
            } else {
                log::error!("Error decrypting nonce");
                false
            }
        }
    }

    /// The new drill has to be explicitly given. Shouldn't be added to the cnac quite yet.
    pub(crate) fn validate_stage_final(cnac: &ClientNetworkAccount, new_drill: &Drill, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<bool> {
        if payload.len() != packet_sizes::do_drill_update::STAGE_FINAL - HDP_HEADER_BYTE_LEN {
            log::error!("Invalid payload len");
            return None;
        }

        if header.cmd_aux == packet_flags::cmd::aux::do_drill_update::FAILURE {
            // In this case, we get the previous drill to validate the security parameters
            if let Some(last_working_drill) = cnac.get_drill(Some(header.drill_version.get())) {
                let sec0 = last_working_drill.get_ultra()[0][12];
                let sec1 = last_working_drill.get_ultra()[1][12];
                let sec2 = last_working_drill.get_high()[1][12];

                if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                    log::error!("Invalid stage failure security parameters");
                    None
                } else {
                    Some(false)
                }
            } else {
                None
            }
        } else {
            if new_drill.get_version() != header.drill_version.get() {
                log::error!("Invalid drill versions specified");
                return None;
            }

            let sec0 = new_drill.get_ultra()[0][12];
            let sec1 = new_drill.get_ultra()[1][12];
            let sec2 = new_drill.get_high()[1][12];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Invalid stage success security parameters");
                None
            } else {
                Some(true)
            }
        }
    }
}

pub(crate) mod do_deregister {
    use zerocopy::LayoutVerified;

    use hyxe_crypt::aes_gcm::AES_GCM_NONCE_LEN_BYTES;
    use hyxe_crypt::drill::Drill;
    use hyxe_crypt::drill::E_OF_X_START_INDEX;
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_flags, packet_sizes};
    use crate::hdp::hdp_packet_processor::includes::PostQuantumContainer;
    use crate::hdp::state_container::VirtualConnectionType;

    /// Returns the payload ID, target cid, and drill
    pub(crate) fn validate_stage0(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(VirtualConnectionType, Drill)> {
        let virtual_connection_type = VirtualConnectionType::deserialize_from(payload)?;

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][0];
            let sec1 = drill.get_ultra()[0][1];
            let sec2 = drill.get_high()[0][2];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Invalid stage 0 security parameters");
                None
            } else {
                Some((virtual_connection_type, drill))
            }
        } else {
            log::error!("Unable to obtain drill for stage 0 packet");
            None
        }
    }

    pub(crate) fn validate_stage1(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<([u8; AES_GCM_NONCE_LEN_BYTES], Drill)> {
        if payload.len() != packet_sizes::do_deregister::STAGE1 - HDP_HEADER_BYTE_LEN {
            log::error!("Invalid stage 1 payload len");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][3];
            let sec1 = drill.get_ultra()[0][4];
            let sec2 = drill.get_high()[0][5];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Invalid stage 1 security parameters");
                None
            } else {
                let nonce_decrypted = drill.decrypt_to_vec(payload, 0, SecurityLevel::LOW).unwrap();
                let mut nonce: [u8; AES_GCM_NONCE_LEN_BYTES] = [0u8; AES_GCM_NONCE_LEN_BYTES];
                for x in 0..AES_GCM_NONCE_LEN_BYTES {
                    nonce[x] = nonce_decrypted[x];
                }
                Some((nonce, drill))
            }
        } else {
            log::error!("Unable to obtain drill for stage 1 packet");
            None
        }
    }

    pub(crate) fn validate_stage2(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, nonce: &[u8; AES_GCM_NONCE_LEN_BYTES], post_quantum: &PostQuantumContainer, payload: &[u8]) -> Option<Drill> {
        if payload.len() != packet_sizes::do_deregister::STAGE2 - HDP_HEADER_BYTE_LEN {
            log::error!("The payload of the packet has an invalid size. Dropping");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][6];
            let sec1 = drill.get_ultra()[0][7];
            let sec2 = drill.get_high()[0][8];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Invalid security parameters on disconnect packet");
                return None;
            }

            if let Ok(decrypted_low_subdrill) = drill.aes_gcm_decrypt_custom_nonce(nonce, post_quantum, &payload) {
                let port_range = drill.get_multiport_width();
                let low_subdrill_real = drill.get_low();
                let mut idx = 0;
                for x in 0..E_OF_X_START_INDEX {
                    for y in 0..port_range {
                        if low_subdrill_real[x][y] != decrypted_low_subdrill[idx] {
                            log::error!("Low subdrills did not match. Dropping");
                            return None;
                        }
                        idx += 1;
                    }
                }

                Some(drill)
            } else {
                log::error!("Invalid stage 2 packet payload");
                None
            }
        } else {
            log::error!("Drill missing for stage 2 do_deregister packet. Dropping");
            None
        }
    }

    /// The new drill has to be explicitly given. Shouldn't be added to the cnac quite yet.
    pub(crate) fn validate_stage_final(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<bool> {
        if payload.len() != packet_sizes::do_deregister::STAGE_FINAL - HDP_HEADER_BYTE_LEN {
            log::error!("Invalid payload len");
            return None;
        }

        // In this case, we get the previous drill to validate the security parameters
        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[0][9];
            let sec1 = drill.get_ultra()[0][10];
            let sec2 = drill.get_high()[0][11];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Invalid stage failure security parameters");
                None
            } else {
                Some(header.cmd_aux == packet_flags::cmd::aux::do_deregister::SUCCESS)
            }
        } else {
            None
        }
    }
}

pub(crate) mod pre_connect {
    use byteorder::{ByteOrder, NetworkEndian};
    use zerocopy::LayoutVerified;

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::drill::Drill;
    use hyxe_crypt::drill_update::DrillUpdateObject;
    use hyxe_crypt::toolset::Toolset;
    use hyxe_nat::hypernode_type::HyperNodeType;
    use hyxe_nat::udp_traversal::NatTraversalMethod;
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::constants::HDP_HEADER_BYTE_LEN;
    use crate::hdp::hdp_packet::{HdpHeader, packet_sizes};
    use crate::hdp::hdp_packet::packet_flags::payload_identifiers;

    // +1 for node type, +2 for minimum 1 wave port inscribed
    const STAGE0_MIN_PAYLOAD_LEN: usize = 1 + 2;
    // +1 for node type, +1 for nat traversal type, +8 for sync_time, +2 for minimum 1 wave port inscribed
    const STAGE1_MIN_PAYLOAD_LEN: usize = 1 + 1 + 8 + 2;

    /// This returns an error if the packet is maliciously invalid (e.g., due to a false packet)
    /// This returns Ok(true) if the system was already synchronized, or Ok(false) if the system needed to synchronize toolsets
    pub fn validate_syn_ack(cnac: &ClientNetworkAccount, pqc: &PostQuantumContainer, payload: &[u8]) -> Result<Drill, ()> {
        if payload.len() != 0 {
            // This implies there exists a toolset in the payload
            let static_auxiliary_drill = unsafe { cnac.get_static_auxiliary_drill() };
            let dou_plaintext = static_auxiliary_drill.aes_gcm_decrypt(0, pqc, payload)
                .map_err(|_| ())?;

            let dou = DrillUpdateObject::deserialize_from_vector(dou_plaintext).map_err(|_| ())?;
            let (_dou, new_base_toolset_drill) = dou.compute_next_recursion(&static_auxiliary_drill, false).ok_or(())?;

            let toolset = Toolset::from((static_auxiliary_drill, new_base_toolset_drill.clone()));
            cnac.replace_toolset(toolset);
            Ok(new_base_toolset_drill)
        } else {
            log::error!("Bad payload len");
            Err(())
        }
    }

    // Returns the adjacent node type, wave ports
    pub fn validate_stage0(new_base_drill: &Drill, cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(HyperNodeType, Vec<u16>)> {
        if payload.len() < STAGE0_MIN_PAYLOAD_LEN {
            return None;
        }

        if header.drill_version.get() != new_base_drill.get_version() {
            log::error!("Header drill version not equal to the new base drill");
            None
        } else {
            let sec0 = new_base_drill.get_ultra()[1][0];
            let sec1 = new_base_drill.get_ultra()[1][1];
            let sec2 = new_base_drill.get_high()[1][2];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Bad security parameters");
                return None;
            }

            let adjacent_node_type = HyperNodeType::from_byte(payload[0])?;
            let port_bytes = &payload[1..];
            if port_bytes.len() % 2 != 0 {
                log::error!("Bad port bytes len");
                return None;
            }
            // Remember: these wll be the UPnP ports if the other end already enabled UPnP. We figure that out later in the stage1 process that calls this closure
            let ports = ports_from_bytes(port_bytes);
            let static_aux_drill = unsafe { cnac.get_static_auxiliary_drill() };
            let new_toolset = Toolset::from((static_aux_drill, new_base_drill.clone()));
            // at this point, the toolsets on both ends are synchronized
            cnac.replace_toolset(new_toolset);
            Some((adjacent_node_type, ports))
        }
    }

    pub fn validate_stage1(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(Drill, HyperNodeType, NatTraversalMethod, i64, Vec<u16>)> {
        if payload.len() < STAGE1_MIN_PAYLOAD_LEN {
            log::error!("Bad payload len");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[1][3];
            let sec1 = drill.get_ultra()[1][4];
            let sec2 = drill.get_high()[1][5];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Bad security parameters");
                return None;
            }

            let adjacent_node_type = HyperNodeType::from_byte(payload[0])?;
            let nat_traversal_method = NatTraversalMethod::from_byte(payload[1])?;
            let sync_time = NetworkEndian::read_i64(&payload[2..10]);
            let port_bytes = &payload[10..];
            if port_bytes.len() % 2 != 0 {
                log::error!("Bad port bytes len");
                return None;
            }

            let adjacent_ports = ports_from_bytes(port_bytes);
            Some((drill, adjacent_node_type, nat_traversal_method, sync_time, adjacent_ports))
        } else {
            log::error!("Unable to find drill");
            None
        }
    }

    pub fn validate_try_next(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(Drill, NatTraversalMethod)> {
        if payload.len() != packet_sizes::do_preconnect::STAGE_TRY_NEXT - HDP_HEADER_BYTE_LEN {
            log::error!("Bad payload len");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[1][6];
            let sec1 = drill.get_ultra()[1][7];
            let sec2 = drill.get_high()[1][8];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Bad security parameters");
                return None;
            }

            Some((drill, NatTraversalMethod::from_byte(payload[0])?))
        } else {
            log::error!("Unable to find drill");
            None
        }
    }

    /// Returns the drill and sync_time
    pub fn validate_try_next_ack(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(Drill, i64)> {
        if payload.len() != packet_sizes::do_preconnect::STAGE_TRY_NEXT_ACK - HDP_HEADER_BYTE_LEN {
            log::error!("Bad payload len");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[1][9];
            let sec1 = drill.get_ultra()[1][10];
            let sec2 = drill.get_high()[1][11];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Bad security parameters");
                return None;
            }

            let sync_time = NetworkEndian::read_i64(payload);
            Some((drill, sync_time))
        } else {
            log::error!("Unable to find drill");
            None
        }
    }

    /// if the payload contains ports, it is expected that those ports are reflective of the ports reserved from the UPnP process.
    /// This returns the drill, the upnp ports, and TCP_ONLY mode
    pub fn validate_final(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(Drill, Option<Vec<u16>>, bool)> {
        if payload.len() % 2 != 0 {
            log::error!("Bad payload len");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[2][0];
            let sec1 = drill.get_ultra()[2][1];
            let sec2 = drill.get_high()[2][2];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Bad security parameters");
                return None;
            }

            let upnp_ports = if payload.len() != 0 {
                Some(ports_from_bytes(payload))
            } else {
                None
            };

            let tcp_only = header.algorithm == payload_identifiers::do_preconnect::TCP_ONLY;

            if tcp_only && upnp_ports.is_some() {
                log::error!("Improper packet configuration. TCP only and Some(upnp_ports) cannot both be true");
                return None;
            }

            Some((drill, upnp_ports, tcp_only))
        } else {
            log::error!("Unable to find drill");
            None
        }
    }

    pub fn validate_begin_connect(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<Drill> {
        if payload.len() != packet_sizes::do_preconnect::STAGE_SUCCESS_ACK - HDP_HEADER_BYTE_LEN {
            log::error!("Bad payload len");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[2][3];
            let sec1 = drill.get_ultra()[2][4];
            let sec2 = drill.get_high()[2][5];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Bad security parameters");
                return None;
            }

            Some(drill)
        } else {
            log::error!("Unable to find drill");
            None
        }
    }

    pub fn validate_server_finished_hole_punch(cnac: &ClientNetworkAccount, header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(Drill, bool)> {
        if payload.len() != packet_sizes::do_preconnect::STAGE_SERVER_DONE - HDP_HEADER_BYTE_LEN {
            log::error!("Bad payload len");
            return None;
        }

        if let Some(drill) = cnac.get_drill(Some(header.drill_version.get())) {
            let sec0 = drill.get_ultra()[2][6];
            let sec1 = drill.get_ultra()[2][7];
            let sec2 = drill.get_high()[2][8];

            if sec0 != header.context_info.get() || sec1 != header.group.get() || sec2 != header.wave_id.get() {
                log::error!("Bad security parameters");
                return None;
            }

            Some((drill, header.algorithm == 1))
        } else {
            log::error!("Unable to find drill");
            None
        }
    }

    #[inline]
    fn ports_from_bytes<T: AsRef<[u8]>>(input: T) -> Vec<u16> {
        let input = input.as_ref();
        let port_count = input.len() / 2; // 2 bytes per u16
        let mut ret = Vec::with_capacity(port_count);

        for x in 0..port_count {
            let start = x * 2;
            let end = start + 1;
            let port = NetworkEndian::read_u16(&input[start..=end]);
            ret.push(port);
        }

        ret
    }
}

pub(crate) mod peer_cmd {
    use bytes::BytesMut;
    use zerocopy::LayoutVerified;

    use hyxe_crypt::drill::Drill;
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::hdp::hdp_packet::HdpHeader;
    use crate::hdp::hdp_packet_processor::includes::{Bytes, PostQuantumContainer};

    /// First-pass validation. Ensures header integrity through AAD-services in AES-GCM
    pub(crate) fn validate<'a, 'b: 'a>(cnac: &ClientNetworkAccount, pqc: &PostQuantumContainer, header: &'b Bytes, mut payload: BytesMut) -> Option<(LayoutVerified<&'a [u8], HdpHeader>, Bytes, Drill)> {
        let bytes = &header[..];
        let header = LayoutVerified::new(bytes)? as LayoutVerified<&[u8], HdpHeader>;
        let drill = cnac.get_drill(Some(header.drill_version.get()))?;
        drill.validate_packet_in_place_split(pqc, bytes, &mut payload).ok()?;
        Some((header, payload.freeze(), drill))
    }
}

pub(crate) mod file {
    use crate::hdp::file_transfer::VirtualFileMetadata;
    use crate::hdp::hdp_packet::HdpHeader;
    use crate::hdp::hdp_packet_processor::includes::LayoutVerified;
    use crate::hdp::state_container::VirtualTargetType;

    pub fn validate_file_header(header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(VirtualTargetType, VirtualFileMetadata)> {
        let split_idx = header.wave_id.get() as usize;
        if payload.len() < split_idx {
            None
        } else {
            let (vtarget_bytes, vfm_bytes) = payload.split_at(split_idx);
            let vtarget = VirtualTargetType::deserialize_from(vtarget_bytes)?;
            let vfm = VirtualFileMetadata::deserialize_from(vfm_bytes)?;
            Some((vtarget, vfm))
        }
    }

    /// return Some(success, object_id) if valid, or None if invalid
    pub fn validate_file_header_ack(header: &LayoutVerified<&[u8], HdpHeader>, payload: &[u8]) -> Option<(bool, u32, VirtualTargetType)> {
        // 16 bytes for the signature
        if payload.len() != 0 {
            let object_id = header.wave_id.get();
            let success = header.group.get() != 0;
            let v_target = VirtualTargetType::deserialize_from(payload)?;
            Some((success, object_id, v_target))
        } else {
            None
        }
    }
}

pub(crate) mod aead {
    use bytes::{Bytes, BytesMut};
    use zerocopy::LayoutVerified;

    use ez_pqcrypto::PostQuantumContainer;
    use hyxe_crypt::drill::Drill;
    use hyxe_user::client_account::ClientNetworkAccount;

    use crate::hdp::hdp_packet::HdpHeader;

    /// First-pass validation. Ensures header integrity through AAD-services in AES-GCM or chacha-poly
    pub(crate) fn validate<'a, 'b: 'a>(cnac: &ClientNetworkAccount, pqc: &PostQuantumContainer, header: &'b Bytes, mut payload: BytesMut) -> Option<(LayoutVerified<&'a [u8], HdpHeader>, Bytes, Drill)> {
        let bytes = &header[..];
        let header = LayoutVerified::new(bytes)? as LayoutVerified<&[u8], HdpHeader>;
        let drill = cnac.get_drill(Some(header.drill_version.get()))?;
        drill.validate_packet_in_place_split(pqc, bytes, &mut payload).ok()?;
        Some((header, payload.freeze(), drill))
    }
}