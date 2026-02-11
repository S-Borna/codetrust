FROM node:20-slim

# Non-root user
RUN useradd --no-create-home --shell /bin/false sandbox
USER sandbox

WORKDIR /tmp

ENTRYPOINT ["node", "-e"]
