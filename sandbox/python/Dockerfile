FROM python:3.12-slim

# No pip install — we only need the standard library for sandbox execution
# User code is injected via stdin or volume mount

# Non-root user
RUN useradd --no-create-home --shell /bin/false sandbox
USER sandbox

WORKDIR /tmp

# No network, no persistent storage — enforced at docker run time
# Resource limits enforced at docker run time (--memory, --cpus)

ENTRYPOINT ["python3", "-c"]
