# syntax=docker/dockerfile:1
# Static musl build in a distroless image: no shell, no package manager, non-root.
FROM rust:1.94-alpine AS build
WORKDIR /app
RUN apk add --no-cache musl-dev
RUN rustup target add x86_64-unknown-linux-musl
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /app/target/x86_64-unknown-linux-musl/release/home-cloud-controller-manager /home-cloud-controller-manager
USER 10001:10001
ENTRYPOINT ["/home-cloud-controller-manager"]
