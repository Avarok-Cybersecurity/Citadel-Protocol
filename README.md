# Avarok Cybersecurity | Citadel Protocol
[![codecov](https://codecov.io/gh/Avarok-Cybersecurity/Lusna/branch/master/graph/badge.svg?token=J739KOHOZR)](https://codecov.io/gh/Avarok-Cybersecurity/Lusna)

## Instructions
OpenSSL and clang are required in order to compile the libraries. View the CI files in .github for an example of getting the code to compile on a bare machine

## Testing instructions
When running unit tests inside `citadel_sdk`, you **must** run the tests with the feature `localhost-testing` enabled, and, allow only one test to run at a time (b/c of a static `Arc<Barrier>` for synchronizing between peers) via `-- --test-threads=1`

example: `cargo test --package citadel_sdk --features=localhost-testing -- --test-threads=1`

Not only does allowing one test at a time help with synchronization, it also helps with reading debug info too.

## WASM
The target triple `wasm32-wasi` is supported. These commands should be executed in order to compile to wasm
```bash
# install wasmtime
curl https://wasmtime.dev/install.sh -sSf | bash
# get the include/build files
wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sysroot-12.0.tar.gz
tar -xvzf wasi-sysroot-12.0.tar.gz
rm wasi-sysroot-12.0.tar.gz
# Set environment variables
export WASI_SDK_DIR="$(pwd)/wasi-sysroot"
export WASMTIME_HOME="$(pwd)/.wasmtime"
export PATH="$WASMTIME_HOME/bin:$PATH"
```

Additionally, the feature `wasm` should be enabled too