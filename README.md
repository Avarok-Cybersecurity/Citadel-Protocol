![](./resources/logo.png)

[![Website shields.io](https://img.shields.io/website-up-down-green-red/http/shields.io.svg)](https://avarok.net)
[![crates.io](https://img.shields.io/crates/v/citadel_sdk.svg)](https://crates.io/crates/citadel_sdk)
[![codecov](https://codecov.io/gh/Avarok-Cybersecurity/Lusna/branch/master/graph/badge.svg?token=J739KOHOZR)](https://codecov.io/gh/Avarok-Cybersecurity/Lusna)
[![Build docs](https://github.com/Avarok-Cybersecurity/Citadel-Protocol/actions/workflows/deploy.yml/badge.svg)](https://avarok-cybersecurity.github.io/Citadel-Protocol/docs/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE-MIT)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE-APACHE)
[![Slack](https://img.shields.io/badge/Slack-4A154B?style=for-the-badge&logo=slack&logoColor=white)](https://avarokcybersecurity.slack.com)
![Linux](https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)
![macOS](https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![iOS](https://img.shields.io/badge/iOS-000000?style=for-the-badge&logo=ios&logoColor=white)
![Android](https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white)

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
cargo install cargo-wasix
curl https://get.wasmer.io -sSfL | sudo sh
export PATH=$PATH:~/.wasmer/bin/

# If on mac, ensure llvm via brew is installed to allow webassembly as a target
brew install llvm

# Install wasi-sysroot
wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sysroot-12.0.tar.gz
tar -xvzf wasi-sysroot-12.0.tar.gz
rm wasi-sysroot-12.0.tar.gz

# Set environment variables. Must use custom version of clang and ar
export WASI_SDK_DIR="$(pwd)/wasi-sysroot"
export PATH="/opt/homebrew/Cellar/llvm/<LATEST_VERSION>/bin/:$PATH"
export AR="/opt/homebrew/Cellar/llvm/<LATEST_VERSION>/bin/llvm-ar"
export CC="/opt/homebrew/Cellar/llvm/<LATEST_VERSION>/bin/clang"
```

Then, to test on wasix, run:
```bash
cargo wasix test --package=citadel_pqcrypto --profile=wasix
```

The profile `wasix` is provided such that the highest level of optimization is used. This is necessary for the wasm target.

# Disclaimer
This project has not (yet) been audited by a third party. While some of the underlying cryptographic primitives come from the verified
Open Quantum Safe (OQS) project and/or the PQClean project, the Kyber library has not yet received an audit (the known answer tests pass, however).

As such, we recommend that, if you choose to use this library and accept the risks associated with its use, you use hybrid cryptography by using either
TLS or QUIC as an underlying protocol to ensure that the protocol is at least as secure as elliptical curve cryptography.

# Authors

[Thomas Braun](https://thomaspbraun.com) - Founder
# Contributing

Contributions are welcome! I have been the only developer for the past 5 years, and, need more people to help make the ecosystem flourish.