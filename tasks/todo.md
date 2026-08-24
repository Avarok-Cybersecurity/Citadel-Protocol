# Audio/Video media transport over Citadel UDP

Plan: ~/.claude/plans/please-add-audio-video-support-sleepy-emerson.md

## Phase 0 — baseline benches
- [x] citadel_crypt/benches/common/mod.rs (SSOT make_ratchets)
- [x] citadel_crypt/benches/udp_media_vs_srtp.rs
- [x] citadel_sdk/benches/udp_media_stream.rs (citadel vs quinn vs raw udp)
- [x] record "before" in bench/RESULTS.md

## Phase 1 — UDP hot path (P0)
- [x] P0-i payload budget + non-fatal TooLarge
- [x] P0-a presize craft_udp_packet + protected_packet_capacity helper
- [x] P0-c explicit UDP security level
- [x] P0-b batch drain
- [x] P0-w platform-generic udp_session_loader
## Phase 1 — P1/P2
- [x] P1-d inbound zero-copy
- [x] P1-e overflow policy + drop counter
- [x] P1-f quinn datagram buffers
- [x] P1-g raw sink w/o UdpFramed
- [x] P2-h WebRTCCompatChannel::recv panic

## Phase 2 — citadel_media crate
- [x] crate skeleton + workspace wiring
- [x] time/error/frame/wire/config
- [x] packetizer/reassembly/jitter/queue/stats/descriptor
- [x] demux wav/ivf (+ IvfWriter)
- [x] unit tests + wasm test

## Phase 3 — citadel_sdk::media + WASM wiring
- [x] error codes
- [x] config/transport/endpoint/sender/receiver
- [x] wasm_rtc unreliable DC + wasm_p2p wiring + WasmIO::spawn_udp_socket_loader

## Phase 4 — examples
- [x] media_audio_send/recv, media_video_send/recv, common.rs

## Phase 5 — fixtures + tests + CI
- [x] fixtures.rs (download+cache+sha256)
- [x] finish_udp_channel in test_common
- [x] tests/udp_media.rs
- [x] wasm_p2p_connect.rs UDP + media
- [x] validate.yml / Makefile.toml

## Phase 6 — measure + record
- [x] after benches → bench/RESULTS.md

## Review (2026-08-23)
All phases complete. Highlights:
- 3.8x better p99 at 50k pps (387.8 -> 103.0 us); beats bare quinn datagrams at 5k & 50k pps
- crypto parity-or-better vs webrtc-srtp AEAD-AES-128-GCM
- WASM: UdpMode::Enabled now yields a real UdpChannel over a negotiated unordered RtcDataChannel
- Old bug fixed: oversize datagram used to silently kill the UDP task
- EOS redesigned to carry frames_sent (reliable-lane EOS was outracing in-flight UDP frames)
- Fixtures pinned by sha256 (sample-3s.wav, vp80-05-sharpness-1428.ivf)
Remaining risk: docker wasm browser test result pending at write time (see final report).

## 2026-08-24 — KEM PR merge + CI flakiness (in progress)
- [x] Root-cause reconnect wedge (3 stacked races) + permanent fixes (PR #276)
- [x] h2 RUSTSEC-2026-0258 (igd-next + hyper 1.x)
- [x] netbeam Stolen flake (real replay bug)
- [x] 60/60 release validation, workspace 575/575, deny green
- [ ] PR #276 CI green -> squash-merge
- [ ] Update PR #273 branch -> CI green -> squash-merge (the KEM PR)
