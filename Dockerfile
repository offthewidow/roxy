FROM rust:1.66-slim-buster AS builder

WORKDIR /tmp/repro

RUN cargo init

COPY Cargo.lock .
COPY Cargo.toml .

RUN cargo build --release
RUN rm -f target/release/deps/repro*

COPY ./src ./src

RUN cargo build --release

FROM debian:buster-slim

COPY --from=builder /tmp/repro/target/release/repro .
COPY config.toml .

EXPOSE 443
CMD ["./repro"]
