FROM registry.access.redhat.com/ubi9/ubi:latest as builder

RUN dnf install -y \
        gcc \
        make \
        openssl-devel \
        pkg-config \
    && dnf clean all

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --profile minimal

ENV PATH="/root/.cargo/bin:${PATH}"

RUN mkdir /build

COPY . /build

WORKDIR /build

RUN cargo build --release

FROM registry.access.redhat.com/ubi9/ubi:latest

COPY --from=builder /build/target/release/trustd /usr/local/bin

ENTRYPOINT ["/usr/local/bin/trustd"]
