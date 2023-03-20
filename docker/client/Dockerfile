FROM rust:1.67 as builder
WORKDIR /usr/src/client
ARG NAT_TYPE
RUN export NAT_TYPE=$NAT_TYPE
COPY . .
COPY ./docker/set_nat.sh ./
RUN apt-get update && apt-get install -y openssl libclang-dev build-essential cmake iptables inetutils-ping && rm -rf /var/lib/apt/lists/*
RUN ./set_nat.sh
RUN cargo install --example client --path ./citadel_sdk --debug
RUN echo "Waiting for STUN servers ..." && sleep 5
CMD ["client"]