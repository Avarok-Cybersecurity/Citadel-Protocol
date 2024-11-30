//! # Argon2 Parameter Auto-tuner
//!
//! Automatically determines optimal Argon2 parameters for password hashing based on system capabilities
//! and performance requirements. This module implements the recommendations from ORY's Argon2 parameter
//! selection guidelines.
//!
//! ## Features
//!
//! * Dynamic parameter tuning based on available system memory
//! * Multi-threaded optimization using available CPU cores
//! * Memory-first tuning strategy for optimal security
//! * Iterative time-cost adjustment
//! * Configurable minimum execution time
//! * Support for custom hash lengths and secret keys
//!
//! ## Usage Example
//!
//! ```rust
//! use citadel_crypt::argon::autotuner::calculate_optimal_argon_params;
//!
//! async fn configure_argon() -> Result<(), CryptError<String>> {
//!     // Configure Argon2 to take at least 500ms
//!     let optimal_params = calculate_optimal_argon_params(
//!         500,                    // minimum milliseconds
//!         None,                   // use default hash length
//!         Some(b"secret".to_vec()) // optional secret key
//!     ).await?;
//!     
//!     println!("Optimal parameters:");
//!     println!("Memory cost: {} KB", optimal_params.mem_cost);
//!     println!("Time cost: {}", optimal_params.time_cost);
//!     println!("Parallelism: {}", optimal_params.lanes);
//!     
//!     Ok(())
//! }
//! ```
//!
//! ## Important Notes
//!
//! * Should be run in release mode for accurate results
//! * Memory cost is automatically capped at available system memory
//! * Parameters are tuned for the specific CPU running the autotuner
//! * Memory-cost is prioritized over time-cost for better security
//! * Results may vary between runs due to system load
//!
//! ## Related Components
//!
//! * `argon_container`: Core Argon2 implementation and settings
//! * `SecBuffer`: Secure memory management for passwords
//! * `CryptError`: Error handling for cryptographic operations
//!

use crate::argon::argon_container::{
    ArgonDefaultServerSettings, ArgonSettings, ArgonStatus, AsyncArgon, DEFAULT_HASH_LENGTH,
};
use crate::misc::CryptError;
use citadel_types::crypto::SecBuffer;
use sysinfo::SystemExt;

/// Uses: https://www.ory.sh/choose-recommended-argon2-parameters-password-hashing/
/// "To reach the desired execution time, you can tweak two variables. It is recommended
/// to start with the highest amount of memory possible and one iteration. Reduce the memory
/// until one hashing operation takes less than your desired duration. Next, advance the
/// number of iterations to approach the desired execution time as close as possible"
pub async fn calculate_optimal_argon_params(
    millis_minimum: u16,
    hash_length: Option<u32>,
    secret: Option<Vec<u8>>,
) -> Result<ArgonDefaultServerSettings, CryptError<String>> {
    if cfg!(debug_assertions) {
        log::warn!(target: "citadel", "You are running the argon autotuner in a debug build. \
        This will give inaccurate results. Use a release build to ensure the best possible performance. \
        Additionally, make sure to only run this autotuner on the CPU that you expect to hash on")
    }

    let system = sysinfo::System::new_all();
    let available_memory_sys = system.free_memory();
    let available_memory = std::cmp::min(available_memory_sys, 1024 * 1024); // ensure we don't start at too low of a value
    let available_memory_kb = available_memory / 1024;
    let hash_length = hash_length.unwrap_or(DEFAULT_HASH_LENGTH);

    let lanes: u32 = num_cpus::get() as _;

    let mut iters = 0;
    let fake_password = SecBuffer::from((0u8..15u8).collect::<Vec<u8>>());

    let mut mem_cost_tuned = false;
    // start with 1
    let mut time_cost = 1;
    let mut mem_cost = available_memory_kb;

    loop {
        let init_time = citadel_io::tokio::time::Instant::now();
        let settings_this_round = ArgonSettings::new_gen_salt(
            vec![],
            lanes,
            hash_length,
            mem_cost as _,
            time_cost,
            secret.clone().unwrap_or_default(),
        );
        log::trace!(target: "citadel", "Settings current: {:?}", settings_this_round);

        match AsyncArgon::hash(fake_password.clone(), settings_this_round)
            .await
            .map_err(|err| CryptError::Encrypt(err.to_string()))?
        {
            ArgonStatus::HashSuccess(_) => {
                let elapsed = init_time.elapsed().as_millis();
                log::trace!(target: "citadel", "Iteration {}: {}ms (Mem cost (KB): {} | time cost: {})", iters, elapsed, mem_cost, time_cost);
                iters += 1;

                if mem_cost_tuned {
                    // edit just the time cost, but only if we haven't reached our target goal
                    if elapsed >= millis_minimum as _ {
                        let final_configuration = ArgonDefaultServerSettings {
                            lanes,
                            hash_length,
                            mem_cost: mem_cost as _,
                            time_cost,
                            secret: secret.clone().unwrap_or_default(),
                        };

                        return Ok(final_configuration);
                    }

                    time_cost += 1;
                } else {
                    // edit just the mem cost. Reduce by 10%, but only if we have went below our target
                    if elapsed < (millis_minimum as f32 / 2f32) as _ {
                        mem_cost_tuned = true;
                        time_cost += 1;
                    } else {
                        let times_over = (elapsed as f32 / millis_minimum as f32).ceil();
                        log::trace!(target: "citadel", "Times over: {}", times_over);

                        let diff = if times_over > 2f32 {
                            mem_cost - (mem_cost as f32 / times_over).floor() as u64
                        } else {
                            (0.20f32 * (mem_cost as f32)) as u64
                        };

                        log::trace!(target: "citadel", "DIFF: {}", diff);
                        mem_cost -= diff;
                    }
                }
            }
            res => {
                return Err(CryptError::Encrypt(format!(
                    "Unable to hash password: {res:?}",
                )))
            }
        }
    }
}
