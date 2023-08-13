FROM rust:1.71-slim-buster AS builder

WORKDIR /tmp/roxy

RUN cargo init

COPY Cargo.lock Cargo.toml ./

RUN cargo build --release
RUN rm -f target/release/deps/roxy*

COPY ./src ./src

RUN cargo build --release

FROM debian:buster-slim

COPY --from=builder /tmp/roxy/target/release/roxy .
COPY config.toml .

EXPOSE 80
EXPOSE 443
CMD ["./roxy"]
