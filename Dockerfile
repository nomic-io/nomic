FROM rust:1.73

RUN apt update && apt install build-essential libssl-dev pkg-config clang git -y
RUN rustup default nightly

WORKDIR /workspace

COPY src/ /workspace/src
COPY build.rs /workspace/
COPY Cargo.lock /workspace/
COPY Cargo.toml /workspace/
COPY rust-toolchain.toml /workspace/
COPY wasm/ /workspace/wasm
COPY rest/ /workspace/rest
COPY networks/ /workspace/networks
COPY targe[t]/ /workspace/target

RUN cargo install --locked --path /workspace/ --target-dir /workspace/target