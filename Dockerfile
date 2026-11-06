# syntax=docker/dockerfile:1
# Static musl build in a distroless image: no shell, no package manager, non-root.
# Multi-arch (linux/amd64, linux/arm64): buildx sets TARGETARCH (amd64/arm64),
# mapped here to the matching musl Rust target. A plain `docker build` uses the
# host arch, so local builds keep working unchanged.
FROM rust:1.94-alpine AS build
ARG TARGETARCH
WORKDIR /app
RUN apk add --no-cache musl-dev
RUN rustup target add ${TARGETARCH}-unknown-linux-musl
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --target ${TARGETARCH}-unknown-linux-musl

FROM gcr.io/distroless/static-debian13:nonroot
ARG TARGETARCH
COPY --from=build /app/target/${TARGETARCH}-unknown-linux-musl/release/home-cloud-controller-manager /home-cloud-controller-manager
USER 10001:10001
ENTRYPOINT ["/home-cloud-controller-manager"]
