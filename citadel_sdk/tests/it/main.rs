//! The SDK's integration tests, in one binary.
//!
//! Each file was its own test binary, and each compiled its own copy of `common` and linked
//! against the whole SDK: 115 binaries took 50-67 minutes to build in the release leg, more
//! than its 80 minute budget left for running them (#391). One binary compiles the shared
//! modules once and links once. Every test keeps its module path under its old file's name, so
//! `test(/^media_fixtures::/)` selects what `--test media_fixtures` did.
//!
//! The browser tests (`../wasm_*.rs`) stay separate binaries: they build for wasm32 and are run
//! by name by wasm-pack.
#![cfg(not(target_family = "wasm"))]

#[path = "../common/mod.rs"]
mod common;
#[path = "../relay_pair/mod.rs"]
mod relay_pair;

// `common` already loads group.rs; the helpers and tests that name it `crate::group` reach it here.
#[cfg(feature = "localhost-testing")]
use common::group;
#[cfg(feature = "localhost-testing")]
#[path = "../../../citadel_wire/tests/common/coturn.rs"]
mod coturn;
#[cfg(feature = "localhost-testing")]
#[path = "../common/dials.rs"]
#[allow(dead_code)]
mod dials;
#[cfg(feature = "localhost-testing")]
#[path = "../common/host_sql_server.rs"]
mod host_sql_server;
#[cfg(feature = "localhost-testing")]
#[path = "../common/kex_identity.rs"]
#[allow(dead_code)]
mod kex_identity;
#[cfg(feature = "localhost-testing")]
#[path = "../common/key_epoch_log.rs"]
#[allow(dead_code)]
mod key_epoch_log;
#[cfg(feature = "localhost-testing")]
#[path = "../common/lane.rs"]
#[allow(dead_code)]
mod lane;
#[cfg(feature = "localhost-testing")]
#[path = "../common/negotiation_shell.rs"]
#[allow(dead_code)]
mod shell;
#[cfg(feature = "localhost-testing")]
#[path = "../common/negotiation_shell_parts.rs"]
#[allow(dead_code)]
mod shell_parts;
#[cfg(feature = "localhost-testing")]
#[path = "../../../citadel_user/tests/common/sqlite_host.rs"]
#[allow(dead_code)]
mod sqlite_host;
#[cfg(feature = "localhost-testing")]
#[path = "../common/key_epoch_steps.rs"]
#[allow(dead_code)]
mod steps;

mod a_cleanly_closed_link_frees_its_session;
mod a_dial_back_during_the_first_exchange_connects_both_ends;
mod a_dial_over_a_live_link_is_answered;
mod a_disconnect_reason_crosses_the_server;
mod a_duplicate_dial_does_not_outlive_its_link;
mod a_group_message_sealed_across_a_removal_is_read;
mod a_group_owners_handler_ends_when_it_returns;
mod a_half_open_session_yields_to_force_login;
mod a_half_open_session_yields_to_its_own_reconnect;
mod a_hierarchy_ends_when_its_owner_leaves;
mod a_join_waits_on_at_most_a_window_of_a_members_messages;
mod a_joiner_reads_everything_sent_after_its_channel_opens;
mod a_key_round_above_the_maximum_is_not_built;
mod a_late_credentialed_login_is_a_timeout;
mod a_level_above_the_maximum_is_refused;
mod a_lost_direct_route_is_not_a_disconnect;
mod a_managed_pair_keeps_its_direct_route;
mod a_members_group_messages_arrive_in_the_order_sent;
mod a_p2p_key_exchange_is_signed_by_each_identity;
mod a_reconnected_peer_can_send_files_again;
mod a_refused_accept_is_not_left_as_a_dial;
mod a_refused_connect_reads_the_same;
mod a_refused_login_can_be_retried_at_once;
mod a_registration_above_the_servers_maximum_is_refused;
mod a_replaced_udp_channel_spares_its_successor;
mod a_second_dial_keeps_the_live_udp_offer;
mod a_server_chooses_whether_transient_accounts_are_allowed;
mod a_server_holds_few_connections_before_sign_in;
mod a_session_releases_what_it_held;
mod a_slow_server_does_not_hold_up_other_connects;
mod a_stalled_transfer_does_not_hold_its_session;
mod a_verified_transfer_is_not_failed_by_the_receivers_disconnect;
mod a_weaker_server_stamp_is_refused;
mod abandon_session;
mod an_accept_for_a_withdrawn_dial_is_refused;
mod an_away_successor_owns_the_group_on_return;
mod an_ended_p2p_connection_releases_its_keys;
mod an_expired_outbound_group_fails_the_senders_handle;
mod an_owner_accepted_join_receives_its_welcome;
mod begin_connect_outlasts_a_slow_punch;
mod broadcast_join_waits_for_owner_group;
mod c2s_connect_abort;
mod c2s_disconnect_reason;
mod c2s_login_deadline;
mod c2s_register_abort;
mod c2s_rekeys_past_the_window;
mod c2s_server_holds_session;
mod c2s_websocket_endpoint;
mod crossed_dials_take_the_stronger_offer;
mod crossed_redials_after_a_refused_exchange_connect;
mod deliberate_drop_is_not_a_lost_link;
mod each_connection_chooses_its_certificate_check;
mod ephemeral_groups;
mod group_closes_when_its_last_member_leaves;
mod group_end_closes_it_for_everyone;
mod group_follows_its_account_to_a_new_device;
mod group_mail_is_bounded;
mod group_mail_is_read_on_return;
mod group_membership_survives_reconnect;
mod group_message_limits;
mod group_message_not_delivered_is_reported;
mod group_messages_across_an_epoch_change_are_not_lost;
mod group_messages_survive_c2s_rekeys;
mod group_owner_follows_its_account_to_a_new_device;
mod group_owner_succession;
mod group_ownership_survives_reconnect;
mod group_rejoin_without_the_owner;
mod group_restore_is_not_captured_by_connect;
mod group_round_trip_over_endpoint;
mod group_send_reports_each_member;
mod group_sender_is_the_session;
mod group_succession_survives_server_restart;
mod group_survives_restart_of_an_external_server;
mod group_survives_server_restart;
mod handshake_expiry;
mod hole_punch_outlives_the_ratchet_window;
mod host_sql_revfs;
mod host_sql_revfs_pull;
mod key_epoch_in_band;
mod legacy_login_rehashes_a_weak_hash;
mod legacy_peer_falls_back_with_a_reason;
mod legacy_registration_follows_the_server_limits;
mod media_fixtures;
mod media_transport_agreement;
mod p2p_class_gating;
mod p2p_path_bytes;
mod p2p_path_outcome;
mod p2p_path_policy;
mod p2p_path_rearm;
mod path_policy_at_connect;
mod pq_recovery;
mod pq_recovery_manage;
mod pq_resume_credential;
mod pq_resume_refusals;
mod pq_sign_in;
mod pq_sign_in_admission;
mod pq_sign_in_admission_after_end;
mod pq_sign_in_admission_after_restart;
mod pq_sign_in_admission_challenge;
mod pq_sign_in_factors;
mod pq_sign_in_host_sql;
mod pq_sign_in_security_key;
mod rebind_keeps_the_direct_path;
mod reconnection_both_c2s;
mod reconnection_c2s;
mod reconnection_markers_reach_ci;
mod reconnection_one_c2s;
mod reconnection_p2p_one_c2s;
mod reconnection_p2p_only;
mod rejections_reach_the_caller;
mod rekey_messaging_test;
mod relay_first_peer_channel;
mod reserve_write_test;
mod revfs_objects_are_sealed_under_the_accounts_key;
mod server_probe;
mod session_security_level_mismatch;
mod signalling_is_relayed_only_within_an_accepted_pair;
mod stress_reconnect_c2s;
mod stress_reconnect_p2p;
mod stress_tests;
mod the_session_suite;
mod turn_relay_p2p;
mod two_accounts_on_one_node_sign_in_at_once;
mod udp_media;
mod udp_media_burst;
mod udp_media_modes;
