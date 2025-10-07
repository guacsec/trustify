FROM registry.access.redhat.com/ubi9/ubi:latest AS builder

RUN dnf install --setop install_weak_deps=false --nodocs -y git python gcc g++ cmake ninja-build openssl-devel xz

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN mkdir /build

COPY . /build

WORKDIR /build

RUN ls

RUN rm rust-toolchain.toml

RUN cargo build --release

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

COPY --from=builder /build/target/release/trustd /usr/local/bin/
