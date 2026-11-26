FROM rust:trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src src
COPY crates crates
COPY client client
COPY deploy/ripsec.example.toml deploy/
RUN cargo build --release --locked

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends iptables && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/ripsec /usr/local/bin/ripsec
COPY deploy/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
