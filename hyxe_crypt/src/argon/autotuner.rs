use crate::argon::argon_container::{ArgonDefaultServerSettings, ArgonSettings, AsyncArgon, ArgonStatus, DEFAULT_HASH_LENGTH};
use crate::misc::CryptError;
use sysinfo::SystemExt;
use crate::prelude::SecBuffer;

/// Uses: https://www.ory.sh/choose-recommended-argon2-parameters-password-hashing/
/// "To reach the desired execution time, you can tweak two variables. It is recommended
/// to start with the highest amount of memory possible and one iteration. Reduce the memory
/// until one hashing operation takes less than your desired duration. Next, advance the
/// number of iterations to approach the desired execution time as close as possible"
pub async fn calculate_optimal_params(millis_minimum: u16, hash_length: Option<u32>, secret: Option<Vec<u8>>) -> Result<ArgonDefaultServerSettings, CryptError<String>> {
    let system = sysinfo::System::new_all();
    let total_memory_kb = std::cmp::max(system.get_available_memory(), 1024*512); // ensure we don't start at too low of a value
    let hash_length = hash_length.unwrap_or(DEFAULT_HASH_LENGTH);

    let lanes: u32 = num_cpus::get() as _;

    let mut iters = 0;
    let fake_password = SecBuffer::from(&[0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15] as &[u8]);

    let mut mem_cost_tuned = false;
    // start with 1
    let mut time_cost = 1;
    let mut mem_cost = total_memory_kb;

    loop {
        let init_time = tokio::time::Instant::now();
        let settings_this_round = ArgonSettings::new_gen_salt(vec![], lanes, hash_length, mem_cost as _, time_cost, secret.clone().unwrap_or_default());
        log::info!("Settings current: {:?}", settings_this_round);

        match AsyncArgon::hash(fake_password.clone(), settings_this_round).await.map_err(|err| CryptError::Encrypt(err.to_string()))? {
            ArgonStatus::HashSuccess(_) => {
                let elapsed = init_time.elapsed().as_millis();
                log::info!("Iteration {}: {}ms (Mem cost (KB): {} | time cost: {})", iters, elapsed, mem_cost, time_cost);
                iters += 1;

                if mem_cost_tuned {
                    // edit just the time cost, but only if we haven't reached our target goal
                    if elapsed >= millis_minimum as _ {
                        let final_configuration = ArgonDefaultServerSettings {
                            lanes,
                            hash_length,
                            mem_cost: mem_cost as _,
                            time_cost,
                            secret: secret.clone().unwrap_or_default()
                        };

                        return Ok(final_configuration)
                    }

                    time_cost += 1;
                } else {
                    // edit just the mem cost. Reduce by 10%, but only if we have went below our target
                    if elapsed < (millis_minimum as f32/2f32) as _ {
                        mem_cost_tuned = true;
                        time_cost += 1;
                    } else {
                        // MEM_COST => elapsed. We want MEM_COST => elapsed where elapsed < target/2
                        let diff = 0.20f32 * (mem_cost as f32);
                        mem_cost -= diff as u64;
                    }
                }
            }
            res => {
                return Err(CryptError::Encrypt(format!("Unable to hash password: {:?}", res)))
            }
        }
    }
}