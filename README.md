# Avarok Cybersecurity | Citadel Protocol
[![codecov](https://codecov.io/gh/Avarok-Cybersecurity/Lusna/branch/master/graph/badge.svg?token=J739KOHOZR)](https://codecov.io/gh/Avarok-Cybersecurity/Lusna)
[![Build docs](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/actions/workflows/deploy.yml/badge.svg)](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/actions/workflows/deploy.yml)
### A post-quantum signal-like protocol that makes developing hyper-secure client-to-server and p2p applications easily
# Whitepaper
The whitepaper for the Citadel Protocol can be found in the repository [here](The_Citadel_Protocol.pdf). Note: this whitepaper has not been updated since July 2022. While the protocol is very similar to what is covered in the whitepaper, it has since evolved. The whitepaper will be synced to the source code in the near future.

## Build instructions
OpenSSL and clang are required in order to compile the libraries. View the CI files in .github for an example of getting the code to compile on a bare machine

## Testing instructions
When running unit tests inside `citadel_sdk`, you **must** run the tests with the feature `localhost-testing` enabled, and, allow only one test to run at a time (b/c of a static `Arc<Barrier>` for synchronizing between peers) via `-- --test-threads=1`

example: `cargo test --package citadel_sdk --features=localhost-testing -- --test-threads=1`

Not only does allowing one test at a time help with synchronization, it also helps with reading debug info too.

## WASM (dev only WIP)
The target triple `wasm32-wasi` is a WIP for support. These commands should be executed in order to compile to wasm
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
export RUSTFLAGS="--cfg tokio_unstable"
# If on Mac M1, make sure to use the clang/ar provided by homebrew. Make sure to replace <LATEST_VERSION>
export PATH="/opt/homebrew/Cellar/llvm/<LATEST_VERSION>/bin/:$PATH"
export AR="/opt/homebrew/Cellar/llvm/<LATEST_VERSION>/bin/llvm-ar"
export CC="/opt/homebrew/Cellar/llvm/<LATEST_VERSION>/bin/clang"
```

Additionally, the feature `wasm` should be enabled when checking/compiling.