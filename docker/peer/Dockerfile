FROM rust:latest as builder
WORKDIR /usr/src/peer
COPY . .
COPY ./docker/set_nat.sh .
COPY ./docker/peer/exec.sh .
RUN apt-get update --fix-missing && apt-get install -y openssl libclang-dev build-essential cmake iptables inetutils-ping net-tools iproute2 && rm -rf /var/lib/apt/lists/*
RUN cargo install --example peer --path ./citadel_sdk --debug
RUN ["chmod", "u+x", "exec.sh"]