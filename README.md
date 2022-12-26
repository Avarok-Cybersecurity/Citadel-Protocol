# Avarok Cybersecurity | Citadel Protocol
[![codecov](https://codecov.io/gh/Avarok-Cybersecurity/Lusna/branch/master/graph/badge.svg?token=J739KOHOZR)](https://codecov.io/gh/Avarok-Cybersecurity/Lusna)

## Instructions
OpenSSL and clang are required in order to compile the libraries. View the CI files in .github for an example of getting the code to compile on a bare machine

## Testing instructions
When running unit tests inside `citadel_sdk`, you **must** run the tests with the feature `localhost-testing` enabled, and, allow only one test to run at a time (b/c of a static `Arc<Barrier>` for synchronizing between peers) via `-- --test-threads=1`

example: `cargo test --package citadel_sdk --features=localhost-testing -- --test-threads=1`

Not only does allowing one test at a time help with synchronization, it also helps with reading debug info too.