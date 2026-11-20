FROM rust:latest as builder
WORKDIR /usr/src/peer
COPY . .
# The toolchain rust-toolchain.toml names, not the base image's.
RUN rustup toolchain install
COPY ./docker/set_nat.sh .
COPY ./docker/peer/exec.sh .
RUN apt-get update --fix-missing && apt-get install --fix-missing -y openssl libclang-dev build-essential cmake iptables inetutils-ping net-tools iproute2 && rm -rf /var/lib/apt/lists/*
# crates.io fetch resilience (mirrors .cargo/config.toml; guards the transient
# "[16] Error in the HTTP2 framing layer" that aborts NAT image builds).
ENV CARGO_NET_RETRY=10 CARGO_HTTP_MULTIPLEXING=false CARGO_NET_GIT_FETCH_WITH_CLI=true
RUN cargo install --locked --example peer --path ./citadel_sdk --debug
RUN ["chmod", "u+x", "exec.sh"]