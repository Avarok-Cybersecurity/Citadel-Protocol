use crate::argon::argon_container::{
    ArgonDefaultServerSettings, ArgonSettings, ArgonStatus, AsyncArgon, DEFAULT_HASH_LENGTH,
};
use crate::misc::CryptError;
use crate::prelude::SecBuffer;
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
    let total_memory_kb = std::cmp::min(system.available_memory(), 1024 * 512); // ensure we don't start at too low of a value
    let hash_length = hash_length.unwrap_or(DEFAULT_HASH_LENGTH);

    let lanes: u32 = num_cpus::get() as _;

    let mut iters = 0;
    let fake_password = SecBuffer::from((0u8..15u8).into_iter().collect::<Vec<u8>>());

    let mut mem_cost_tuned = false;
    // start with 1
    let mut time_cost = 1;
    let mut mem_cost = total_memory_kb;

    loop {
        let init_time = tokio::time::Instant::now();
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
            .map_err(|err| CryptError::Encrypt(err.message))?
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
