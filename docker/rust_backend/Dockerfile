# Dockerfile

FROM silkeh/clang:13 as clang


FROM rust:latest as rust


FROM jonoh/sccache-rust as sccache


FROM rust:latest as integration_tests
WORKDIR /app

COPY --from=clang /usr/local/lib/libclang.so /app
COPY --from=sccache /usr/local/bin/sccache /app
ENV LIBCLANG_PATH=/app
ENV RUSTC_WRAPPER=/app/sccache
ENV DCMAKE_C_COMPILER_LAUNCHER=sccache
ENV DCMAKE_CXX_COMPILER_LAUNCHER=sccache

COPY . /app

EXPOSE 25021/tcp
EXPOSE 25021/udp

RUN cargo test --package hyxe_user