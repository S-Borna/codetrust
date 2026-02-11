FROM rust:1.77-slim

# Non-root user
RUN useradd --no-create-home --shell /bin/false sandbox
USER sandbox

WORKDIR /tmp

# Rust code is compiled and run in one step via rustc + execute
ENTRYPOINT ["sh", "-c", "rustc /tmp/main.rs -o /tmp/main && /tmp/main"]
