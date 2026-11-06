# syntax=docker/dockerfile:1
# Static musl build in a distroless image: no shell, no package manager, non-root.
# Multi-arch: the CI workflow passes RUST_TARGET per platform as a build arg
# (x86_64-unknown-linux-musl / aarch64-unknown-linux-musl). The default keeps
# a plain local `docker build` working on x86_64 hosts.
FROM rust:1.94-alpine AS build
ARG RUST_TARGET=x86_64-unknown-linux-musl
WORKDIR /app
RUN apk add --no-cache musl-dev
RUN rustup target add ${RUST_TARGET}
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --target ${RUST_TARGET}

FROM gcr.io/distroless/static-debian13:nonroot
ARG RUST_TARGET=x86_64-unknown-linux-musl
COPY --from=build /app/target/${RUST_TARGET}/release/home-cloud-controller-manager /home-cloud-controller-manager
USER 10001:10001
ENTRYPOINT ["/home-cloud-controller-manager"]
