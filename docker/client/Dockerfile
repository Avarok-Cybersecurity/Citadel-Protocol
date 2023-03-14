FROM rust:1.67 as builder
WORKDIR /usr/src/client
COPY . .
RUN apt-get update && apt-get install -y openssl libclang-dev build-essential cmake && rm -rf /var/lib/apt/lists/*
RUN cargo install --example client --path ./citadel_sdk --debug
CMD ["client"]