# syntax=docker/dockerfile:1
# ---- build stage ------------------------------------------------------------
FROM rust:1.75-bookworm AS build
WORKDIR /src
COPY . .
# Locked, warning-free release build (deny(warnings) is in every crate root).
RUN cargo build --release --locked -p iwf-node -p iwf-benchmark

# ---- runtime stage: distroless, non-root ------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/iwf-node /usr/local/bin/iwf-node
COPY --from=build /src/target/release/loadgen /usr/local/bin/loadgen
COPY config/rules.yaml /etc/iwf/rules.yaml
USER nonroot
EXPOSE 3868 8080 9090
ENTRYPOINT ["/usr/local/bin/iwf-node"]
