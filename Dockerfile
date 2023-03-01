FROM rust:1.66
WORKDIR /usr/src/repro
COPY . .
RUN cargo build --release
EXPOSE 443
CMD ./target/release/repro