#[cfg(test)]
mod tests {
    use hyxe_crypt::drill::SecurityLevel;
    use hyxe_fs::file_crypt_scrambler::scramble_encrypt_file;
    use tokio::sync::mpsc::channel;
    use bytes::BufMut;
    use std::time::Instant;
    use hyxe_crypt::net::crypt_splitter::{GroupReceiver, GroupReceiverStatus};
    use std::io::Write;

    fn setup_log() {
        std::env::set_var("RUST_LOG", "trace");
        env_logger::init();
        log::trace!("TRACE enabled");
        log::info!("INFO enabled");
        log::warn!("WARN enabled");
        log::error!("ERROR enabled");
    }

    #[tokio::test]
    async fn encrypt_decrypt_test() {
        setup_log();
        fn gen(drill_vers: u32) -> (HyperRatchet, HyperRatchet) {
            let mut alice_base = HyperRatchetConstructor::new_alice(None, 0, 0, None);
            let bob_base = HyperRatchetConstructor::new_bob(0, 0, drill_vers, alice_base.stage0_alice()).unwrap();
            alice_base.stage1_alice(bob_base.stage0_bob().unwrap()).unwrap();

            (alice_base.finish().unwrap(), bob_base.finish().unwrap())
        }

        let (alice, _bob) = gen(0);
        let security_level = SecurityLevel::LOW;
        const HEADER_LEN: usize = 52;
        // // C:\\satori.net\\target\\debug\\hyxewave
        let path = "/Users/nologik/Downloads/TheBridge.pdf";
        let cmp = include_bytes!("/Users/nologik/Downloads/TheBridge.pdf");
        let std_file = std::fs::File::open(path).unwrap();
        let (group_sender_tx, mut group_sender_rx) = channel(1);
        let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let (bytes, num_groups) = scramble_encrypt_file(std_file, None,99, group_sender_tx, stop_rx, security_level, alice.clone(), HEADER_LEN, 9, 0, |_, _, _, _, packet| {
            for x in 0..HEADER_LEN {
                packet.put_u8((x % 255) as u8)
            }
        }).unwrap();

        println!("Ran function, now awaiting results ...");
        let mut i: usize = 0;
        let now = Instant::now();
        let mut bytes_ret = Vec::new();
        let mut compressed_len: usize = 0;
        let mut decompressed_len: usize = 0;

        while let Some(gs) =  group_sender_rx.recv().await {
            let mut gs = gs.unwrap();
            let config = gs.get_receiver_config();
            //println!("RECEIVED GS {} w {} packets", i, gs.packets_in_ram.len());
            let mut receiver = GroupReceiver::new(config.clone(),0, 0);
            //println!("{:?}", &receiver);
            let group_id = config.group_id;
            let mut seq = 0;
            let now = Instant::now();
            'here: while let Some(mut packet) = gs.get_next_packet() {
                let packet_payload = packet.packet.split_off(HEADER_LEN);
                let result = receiver.on_packet_received(group_id as u64, packet.vector.true_sequence, packet.vector.wave_id, &alice, packet_payload);
                //dbg!(&result);
                match result {
                    GroupReceiverStatus::GROUP_COMPLETE(group_id) => {
                        bytes_ret.extend_from_slice(receiver.finalize().as_slice());
                        /*
                        let mut bytes = receiver.finalize();
                        //let slice = bytes.as_slice();
                        println!("Compressed len: {}", bytes.len());
                        compressed_len += bytes.len();
                        //let len = flate2::bufread::DeflateDecoder::new(bytes.as_slice()).read_to_end(&mut bytes_ret).unwrap();
                        let decompressed = flate3::inflate(bytes.as_slice());
                        println!("Decompressed len: {:?}", decompressed.len());
                        decompressed_len += decompressed.len();
                        bytes_ret.extend(decompressed.into_iter());*/
                        break 'here;
                    }

                    _ => {}
                }
                seq += 1;
            }
            i += 1;
        }

        let delta = now.elapsed();
        let megabytes = bytes as f32 / 1_000_000f32;
        let mbs = megabytes / delta.as_secs_f32();
        println!("Done receiving all. {} time, {} bytes. {} Mb/s", delta.as_millis(), bytes, mbs);
        //println!("Decompressed len: {} | Compressed len: {} | Ratio: {}", decompressed_len, compressed_len, (decompressed_len as f32 / compressed_len as f32));

        assert_eq!(bytes, bytes_ret.len());
        if bytes_ret.as_slice() != cmp as &[u8] {
            println!("{:?} != {:?}", &bytes_ret.as_slice()[..10], &cmp[..10]);
            println!("{:?} != {:?}", &bytes_ret.as_slice()[bytes_ret.len()-10..], &cmp[cmp.len()-10..]);
            panic!("Vectors not equal")
        }
    }

    use hyxe_crypt::hyper_ratchet::HyperRatchet;
    use hyxe_crypt::hyper_ratchet::constructor::HyperRatchetConstructor;

    #[test]
    fn create_dummy_file() {
        const LEN: usize = 4_187_593_113; // 3.9 gigabytes
        let mut file = std::fs::File::create("C:/Users/tbrau/dummy.bin").unwrap();
        let slab = (0..u8::MAX).into_iter().collect::<Vec<u8>>();
        let mut written = 0;
        while written < LEN {
            file.write_all(slab.as_slice()).unwrap();
            written += u8::MAX as usize;
        }

        file.flush().unwrap();
        file.sync_all().unwrap();
    }
}