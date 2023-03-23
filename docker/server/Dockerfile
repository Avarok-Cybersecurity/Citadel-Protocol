FROM rust:1.67 as builder
WORKDIR /usr/src/server
COPY . .
COPY ./docker/set_nat.sh .
COPY ./docker/server/exec.sh .
RUN apt-get update && apt-get install -y openssl libclang-dev build-essential cmake iptables inetutils-ping net-tools iproute2 && rm -rf /var/lib/apt/lists/*
#RUN ./set_nat.sh
#RUN cargo install --example server --path ./citadel_sdk --debug
#CMD ["server"]
RUN ["chmod", "u+x", "exec.sh"]