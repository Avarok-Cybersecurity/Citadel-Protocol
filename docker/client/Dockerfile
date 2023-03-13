FROM rust:1.67 as builder
ARG NAT_TYPE
RUN export NAT_TYPE=$NAT_TYPE
WORKDIR /usr/src/client
COPY . .
COPY ./docker/set_nat.sh ./set_nat.sh
RUN apt-get update && apt-get install -y openssl libclang-dev build-essential cmake iptables iproute2 && rm -rf /var/lib/apt/lists/*
RUN ./set_nat.sh
RUN cargo install --example client --path ./citadel_sdk --debug
CMD ["client"]