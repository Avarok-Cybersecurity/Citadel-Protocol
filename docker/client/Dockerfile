FROM rust:latest as builder
WORKDIR /usr/src/client
COPY . .
COPY ./docker/set_nat.sh .
COPY ./docker/client/exec.sh .
RUN apt-get update --fix-missing && apt-get install -y openssl libclang-dev build-essential cmake iptables inetutils-ping net-tools iproute2 && rm -rf /var/lib/apt/lists/*
RUN cargo install --example client --path ./citadel_sdk --debug
RUN ["chmod", "u+x", "exec.sh"]