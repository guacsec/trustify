FROM registry.access.redhat.com/ubi10/ubi:latest AS runtime-dependencies

# Stage runtime libraries for the package-manager-free Micro image, as in the release image.
# Managed PostgreSQL also needs Kerberos, zstd, LZ4, and libxml2.
RUN dnf install --installroot /stage --setop install_weak_deps=false --nodocs -y zlib openssl-libs ca-certificates krb5-libs libzstd lz4-libs libxml2 && \
    dnf clean all --installroot /stage

FROM registry.access.redhat.com/ubi10/ubi:latest AS builder

RUN dnf install --setop install_weak_deps=false --nodocs -y git python gcc g++ cmake ninja-build openssl-devel xz

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

RUN mkdir /build

COPY . /build

WORKDIR /build

RUN ls

RUN cargo build --release

FROM registry.access.redhat.com/ubi10/ubi-micro:latest

COPY --from=runtime-dependencies /stage/ /

COPY --from=builder /build/target/release/trustd /usr/local/bin/
