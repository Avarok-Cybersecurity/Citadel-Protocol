//! A rekey must not run its KEM work on the executor thread.
//!
//! `new_alice` generates keypairs, `new_bob` encapsulates and `stage1_alice`
//! decapsulates: up to a second each in a debug build. Run inline, they stall every task sharing that
//! thread, and wall-clock bounds elsewhere (the hole punch, timeouts on local
//! requests) expire while the task that would have met them cannot run.
//!
//! Deterministic, not timed: the test ratchet's constructors wait until a
//! "pump" task on the same current-thread runtime has run. On the executor
//! thread the pump can never run, so the wait times out and is recorded. Off
//! it, the pump releases the wait within a tick.

use super::tests::{
    run_round_one_node_only, setup_endpoint_containers, TestRatchetManager, TEST_PSKS,
};
use crate::endpoint_crypto_container::EndpointRatchetConstructor;
use crate::prelude::CryptError;
use crate::ratchets::entropy_bank::EntropyBank;
use crate::ratchets::ratchet_manager::{RatchetManager, RatchetManagerSink, RatchetManagerStream};
use crate::ratchets::stacked::constructor::{
    AliceToBobTransfer, BobToAliceTransfer, StackedRatchetConstructor,
};
use crate::ratchets::stacked::StackedRatchet;
use crate::ratchets::Ratchet;
use citadel_io::tokio;
use citadel_pqcrypto::constructor_opts::ConstructorOpts;
use citadel_pqcrypto::PostQuantumContainer;
use citadel_types::prelude::{EncryptionAlgorithm, KemAlgorithm, SecurityLevel};
use serde::{Deserialize, Serialize};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

/// Longer than any honest wait for a pump tick; short enough that a red run
/// finishes.
const GATE_TIMEOUT: Duration = Duration::from_secs(5);

struct GateState {
    armed: bool,
    pump_ticks: u64,
    alice_calls: u32,
    bob_calls: u32,
    stage1_calls: u32,
    starved_calls: u32,
}

#[derive(Clone, Copy)]
enum KemStep {
    NewAlice,
    NewBob,
    Stage1Alice,
}

static GATE: Mutex<GateState> = Mutex::new(GateState {
    armed: false,
    pump_ticks: 0,
    alice_calls: 0,
    bob_calls: 0,
    stage1_calls: 0,
    starved_calls: 0,
});
static GATE_CV: Condvar = Condvar::new();

/// Returns once the pump has ticked since entry, or records a starvation.
fn wait_for_the_executor(step: KemStep) {
    let mut state = GATE.lock().unwrap();
    if !state.armed {
        return;
    }
    match step {
        KemStep::NewAlice => state.alice_calls += 1,
        KemStep::NewBob => state.bob_calls += 1,
        KemStep::Stage1Alice => state.stage1_calls += 1,
    }
    let entry_tick = state.pump_ticks;
    let (mut state, result) = GATE_CV
        .wait_timeout_while(state, GATE_TIMEOUT, |s| s.pump_ticks == entry_tick)
        .unwrap();
    if result.timed_out() {
        state.starved_calls += 1;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct GatedRatchet(StackedRatchet);

impl Ratchet for GatedRatchet {
    type Constructor = GatedConstructor;

    fn get_default_security_level(&self) -> SecurityLevel {
        self.0.get_default_security_level()
    }

    fn get_message_pqc_and_entropy_bank_at_layer(
        &self,
        idx: Option<usize>,
    ) -> Result<(&PostQuantumContainer, &EntropyBank), CryptError> {
        self.0.get_message_pqc_and_entropy_bank_at_layer(idx)
    }

    fn get_scramble_pqc_and_entropy_bank(&self) -> (&PostQuantumContainer, &EntropyBank) {
        self.0.get_scramble_pqc_and_entropy_bank()
    }

    fn get_next_constructor_opts(&self) -> Vec<ConstructorOpts> {
        self.0.get_next_constructor_opts()
    }

    fn message_ratchet_count(&self) -> usize {
        self.0.message_ratchet_count()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct GatedConstructor(StackedRatchetConstructor);

impl EndpointRatchetConstructor<GatedRatchet> for GatedConstructor {
    type AliceToBobWireTransfer = AliceToBobTransfer;
    type BobToAliceWireTransfer = BobToAliceTransfer;

    fn new_alice(opts: Vec<ConstructorOpts>, cid: u64, new_version: u32) -> Option<Self> {
        wait_for_the_executor(KemStep::NewAlice);
        StackedRatchetConstructor::new_alice(opts, cid, new_version).map(Self)
    }

    fn new_bob<T: AsRef<[u8]>>(
        cid: u64,
        opts: Vec<ConstructorOpts>,
        transfer: Self::AliceToBobWireTransfer,
        psks: &[T],
    ) -> Option<Self> {
        wait_for_the_executor(KemStep::NewBob);
        StackedRatchetConstructor::new_bob(cid, opts, transfer, psks).map(Self)
    }

    fn stage0_alice(&self) -> Option<Self::AliceToBobWireTransfer> {
        self.0.stage0_alice()
    }

    fn stage0_bob(&mut self) -> Option<Self::BobToAliceWireTransfer> {
        self.0.stage0_bob()
    }

    fn stage1_alice<T: AsRef<[u8]>>(
        &mut self,
        transfer: Self::BobToAliceWireTransfer,
        psks: &[T],
    ) -> Result<(), CryptError> {
        wait_for_the_executor(KemStep::Stage1Alice);
        self.0.stage1_alice(transfer, psks)
    }

    fn update_version(&mut self, version: u32) -> Option<()> {
        self.0.update_version(version)
    }

    fn finish_with_custom_cid(self, cid: u64) -> Option<GatedRatchet> {
        self.0.finish_with_custom_cid(cid).map(GatedRatchet)
    }

    fn finish(self) -> Option<GatedRatchet> {
        self.0.finish().map(GatedRatchet)
    }
}

fn gated_managers() -> (
    TestRatchetManager<GatedRatchet, ()>,
    TestRatchetManager<GatedRatchet, ()>,
) {
    let (alice_container, bob_container) = setup_endpoint_containers::<GatedRatchet>(
        SecurityLevel::Standard,
        EncryptionAlgorithm::AES_GCM_256,
        KemAlgorithm::MlKem,
    );
    let (tx_alice, rx_bob) = futures::channel::mpsc::unbounded();
    let (tx_bob, rx_alice) = futures::channel::mpsc::unbounded();
    let alice = RatchetManager::new(
        Box::new(tx_alice)
            as Box<dyn RatchetManagerSink<(), Error = futures::channel::mpsc::SendError>>,
        Box::new(rx_alice) as Box<dyn RatchetManagerStream<()>>,
        alice_container,
        TEST_PSKS,
    );
    let bob = RatchetManager::new(
        Box::new(tx_bob)
            as Box<dyn RatchetManagerSink<(), Error = futures::channel::mpsc::SendError>>,
        Box::new(rx_bob) as Box<dyn RatchetManagerStream<()>>,
        bob_container,
        TEST_PSKS,
    );
    (alice, bob)
}

#[tokio::test(flavor = "current_thread")]
async fn a_rekey_keeps_the_executor_free_while_it_builds_keys() {
    // Built before arming: the initial ratchets are constructed synchronously.
    let (alice, bob) = gated_managers();
    GATE.lock().unwrap().armed = true;

    let pump = tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_millis(1)).await;
            GATE.lock().unwrap().pump_ticks += 1;
            GATE_CV.notify_all();
        }
    });

    run_round_one_node_only(alice, bob).await;
    pump.abort();

    let state = GATE.lock().unwrap();
    assert!(
        state.alice_calls >= 1 && state.bob_calls >= 1 && state.stage1_calls >= 1,
        "the rekey did not run every KEM step, so the gate proved nothing \
         (new_alice={}, new_bob={}, stage1_alice={})",
        state.alice_calls,
        state.bob_calls,
        state.stage1_calls
    );
    assert_eq!(
        state.starved_calls, 0,
        "{} KEM step(s) ran on the executor thread: the runtime could not \
         run a single other task until they finished",
        state.starved_calls
    );
}
