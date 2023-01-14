# Avarok Cybersecurity | Citadel Protocol
[![Website shields.io](https://img.shields.io/website-up-down-green-red/http/shields.io.svg)](https://avarok.net)
[![codecov](https://codecov.io/gh/Avarok-Cybersecurity/Lusna/branch/master/graph/badge.svg?token=J739KOHOZR)](https://codecov.io/gh/Avarok-Cybersecurity/Lusna)
[![Build docs](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/actions/workflows/deploy.yml/badge.svg)](https://avarok-cybersecurity.github.io/Citadel-Protocol/docs/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)
[![Slack](https://img.shields.io/badge/Slack-4A154B?style=for-the-badge&logo=slack&logoColor=white)](https://avarokcybersecurity.slack.com)
### A post-quantum signal-like protocol that makes developing hyper-secure client-to-server and p2p applications easy
# Whitepaper
The whitepaper for the Citadel Protocol can be found in the repository [here](The_Citadel_Protocol.pdf). Note: this whitepaper has not been updated since July 2022. While the protocol is very similar to what is covered in the whitepaper, it has since evolved. The whitepaper will be synced to the source code in the near future.

# Documentation
For examples on building applications, please check [the docs](https://avarok-cybersecurity.github.io/Citadel-Protocol/docs/)

## Build instructions
OpenSSL and Clang are required in order to compile the libraries. View the CI files in .github for an example of getting the code to compile on a bare machine.
Alternatively, you can run the following command to setup the environment

```shell
cargo make install
```

## Testing instructions
When running unit tests inside `citadel_sdk`, you **must** use the Makefile. The Makefile contains special
flags and environmental variables set to interface with `cargo test`. First, install cargo make:

```shell
cargo install --force cargo-make
```

To run tests locally with limited setup, run:

```shell
cargo make test-local
```

To run a comprehensive set of tests that require a SQL and/or redis server set up (please check the description in `Makefile.toml` for help setting up the environment variables),
run:

```shell
cargo make test
```

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

# Disclaimer
This project has not (yet) been audited by a third party. While some of the underlying cryptographic primitives come from the verified
Open Quantum Safe (OQS) project and/or the PQClean project, the Kyber library has not yet received an audit (the known answer tests pass, however).

As such, we recommend that, if you choose to use this library and accept the risks associated with its use, you use hybrid cryptography by using either
TLS or QUIC as an underlying protocol to ensure that the protocol is at least as secure as elliptical curve cryptography.

# Authors

[Thomas Braun](https://thomaspbraun.com) - Founder
# Contributing

Contributions are welcome! I have been the only developer for the past 5 years, and, need more people to help make the ecosystem flourish.