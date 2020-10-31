/*
 * Copyright (c) 2019. The information/code/data contained within this file and all other files with the same copyright are protected under US Statutes. You must have explicit written access by Thomas P. Braun in order to access, view, modify, alter, or apply this code in any context commercial or non-commercial. If you have this code but were not given explicit written access by Thomas P. Braun, you must destroy the information herein for legal safety. You agree that if you apply the concepts herein without any written access, Thomas P. Braun will seek the maximum possible legal retribution.
 */

/// Time manipulation tools
pub mod temporal {
    use std::fmt::{Display, Error, Formatter};
    use std::time::Instant;
    use crate::statics::RUNTIME;
    use crate::temporal::temporal::unsafes::get_timestamp_differential;

    use self::unsafes::{force_get_runtime, force_get_runtime_timestamp};

    /// Provides a relative time to the start of the program. Useful for tracking lifetimes of objects and subroutines
    pub struct RelativeTimeStamp {
        secs: i64,
        ns: i32,
        initial: ObjectBirthTime,
    }

    struct ObjectBirthTime {
        secs: i64,
        ns: i32,
    }

    impl From<(i64, i32)> for RelativeTimeStamp {
        fn from(input: (i64, i32)) -> Self {
            Self { secs: input.0, ns: input.1, initial: ObjectBirthTime { secs: input.0, ns: input.1 } }
        }
    }

    impl Display for RelativeTimeStamp {
        fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
            let lifetime = self.get_lifetime().unwrap();
            write!(f, "[Timestamp] Birth: {}s + {}ns\n\t\t\tLifetime: {}s {} ns\n\t\t\tLast Delta: {}s + {}ns", self.initial.secs, self.initial.ns, lifetime.0, lifetime.1, self.secs, self.ns)
        }
    }

    impl RelativeTimeStamp {
        /// Get the present runtime
        pub fn now() -> Self {
            let ts = unsafe { force_get_runtime_timestamp() };
            Self::from(ts)
        }

        /// Returns a RelativeTimeStamp that shows the difference in time since object initialization
        pub fn time_elapsed(&self) -> Result<Self, std::io::Error> {
            unsafe {
                get_timestamp_differential(&force_get_runtime_timestamp(), &(self.secs, self.ns)).and_then(|delta_obj| {
                    Ok(RelativeTimeStamp::from(delta_obj))
                })
            }
        }

        /// All timestamps have an initial immutable timestamp representing the time when the object began to exist.
        /// This function returns the total lifetime of the object
        pub fn get_lifetime_as_object(&self) -> Result<Self, std::io::Error> {
            unsafe {
                get_timestamp_differential(&force_get_runtime_timestamp(), &(self.initial.secs, self.initial.ns)).and_then(|delta_obj| {
                    Ok(RelativeTimeStamp::from(delta_obj))
                })
            }
        }

        /// Returns the raw lifetime of the object
        pub fn get_lifetime(&self) -> Result<(i64, i32), std::io::Error> {
            unsafe {
                get_timestamp_differential(&force_get_runtime_timestamp(), &(self.initial.secs, self.initial.ns)).and_then(|delta_obj| {
                    Ok(delta_obj)
                })
            }
        }

        /// Updates the current object to the most recent runtime
        pub fn update(&mut self) {
            let new = unsafe { Self::from(force_get_runtime_timestamp()) };
            self.secs = new.secs;
            self.ns = new.ns;
        }

        /// Updates self and return the delta since last update call or initialization
        pub fn update_and_get_delta(&mut self) -> Result<(i64, i32), std::io::Error> {
            unsafe { RUNTIME.update_timestamp_and_get_delta(self) }
        }

        /// All timestamps have an initial immutable timestamp representing the time when the object began to exist.
        /// This determines if the current timestamp of the object is equal to the initial object's timestamp
        pub fn is_initial(&self) -> bool {
            self.secs == self.initial.secs && self.ns == self.initial.ns
        }
    }


    /// Allows convenient access of runtime. NOTE: USES UNSAFES!
    pub trait RuntimeDelta {
        /// Returns time delta between the present and the initial runtime measurement in nanoseconds
        fn get_elapsed_system_time_ns(&self) -> i64;

        /// Returns time delta between the present and the initial runtime measurement in the format of seconds
        fn get_elapsed_system_time_secs(&self) -> i64;

        /// Returns a pretty-print version of the runtime
        fn get_displayable_runtime(&self) -> String;

        /// Returns the relative time delta since program initialization
        fn get_raw_runtime(&self) -> f64;

        /// Returns the timestamp relative to the program initialization
        fn get_timestamp(&self) -> RelativeTimeStamp;

        /// Returns the raw time differential components in (seconds (absolute), nanoseconds (relative))
        unsafe fn get_raw_timestamp(&self) -> (i64, i32);

        /// Update a timestamp and return the delta
        unsafe fn update_timestamp_and_get_delta(&self, timestamp: &mut RelativeTimeStamp) -> Result<(i64, i32), std::io::Error>;
    }

    impl RuntimeDelta for RUNTIME {
        fn get_elapsed_system_time_ns(&self) -> i64 {
            unsafe {
                let (secs_delta, nsec_delta) = force_get_runtime_timestamp();
                (secs_delta * unsafes::NSEC_PER_SEC as i64) + nsec_delta as i64
            }
        }

        fn get_elapsed_system_time_secs(&self) -> i64 {
            unsafe {
                force_get_runtime_timestamp().0
            }
        }

        fn get_displayable_runtime(&self) -> String {
            unsafe {
                let (secs_dif, nsec_dif) = force_get_runtime_timestamp();
                format!("{}s {}ns", secs_dif, nsec_dif)
            }
        }

        fn get_raw_runtime(&self) -> f64 {
            unsafe { force_get_runtime() }
        }

        unsafe fn get_raw_timestamp(&self) -> (i64, i32) {
            force_get_runtime_timestamp()
        }

        fn get_timestamp(&self) -> RelativeTimeStamp {
            RelativeTimeStamp::now()
        }


        #[inline]
        unsafe fn update_timestamp_and_get_delta(&self, ts: &mut RelativeTimeStamp) -> Result<(i64, i32), std::io::Error> {
            let present = force_get_runtime_timestamp();
            let ret = get_timestamp_differential(&present, &(ts.secs, ts.ns)).unwrap();
            ts.secs = ret.0;
            ts.ns = ret.1;
            Ok(ret)
        }
    }

    /// Contains the memory-manipulation functions which are used for tracking time and are inherently unsafe as they transmute memory
    pub mod unsafes {
        use std::str::FromStr;

        pub(crate) static NSEC_PER_SEC: i32 = 1_000_000_000;
        //use crate::temporal::temporal::NSEC_PER_SEC;

        /// This is the root function for getting elapsed time
        /// Returns time delta between the present and the initial runtime measurement in the format of seconds:nanoseconds
        #[inline]
        pub(super) unsafe fn force_get_runtime_timestamp() -> (i64, i32) {
            let initial = std::mem::transmute_copy::<super::Instant, (i64, i32)>(&*super::RUNTIME.read());
            let present = std::mem::transmute_copy::<super::Instant, (i64, i32)>(&super::Instant::now());
            //println!("{} {}\n{} {}", present.0, present.1, initial.0, initial.1);
            get_timestamp_differential(&present, &initial).unwrap()
        }

        #[inline]
        pub(super) unsafe fn get_timestamp_differential(present: &(i64, i32), past_ref: &(i64, i32)) -> Result<(i64, i32), std::io::Error> {
            let secs_dif = present.0 - past_ref.0;

            assert!(secs_dif >= 0);
            //println!("secs_dif: {}", secs_dif);
            match secs_dif {
                0 => {
                    debug_assert!(present.1 > past_ref.1);
                    Ok((0, present.1 - past_ref.1))
                }
                n => {
                    let (mut sec_total, mut nsec_total) = (0, 0);
                    // Count up to 1.
                    nsec_total += NSEC_PER_SEC - past_ref.1;
                    // count seconds
                    if secs_dif > 1 {
                        for _ in 1..n {
                            //println!("Add 1");
                            sec_total += 1;
                        }
                    } else {
                        sec_total = 0;
                    }


                    nsec_total += present.1;
                    if nsec_total > NSEC_PER_SEC {
                        //println!("... add 1 more");
                        Ok((sec_total + 1, nsec_total - NSEC_PER_SEC))
                    } else {
                        Ok((sec_total, nsec_total))
                    }
                }
            }
        }

        /// Returns the default seconds.nanoseconds format
        pub(super) unsafe fn force_get_runtime() -> f64 {
            let (secs_dif, nsec_dif) = force_get_runtime_timestamp();
            let merge = format!("{}.{}", secs_dif, nsec_dif);
            let merge = merge.as_str();
            f64::from_str(merge).unwrap_or(0.0f64)
        }
    }
}



