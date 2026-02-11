FROM golang:1.22-alpine

# Non-root user
RUN adduser -D -s /bin/false sandbox
USER sandbox

WORKDIR /tmp

# Go code is compiled and executed via 'go run'
ENTRYPOINT ["go", "run", "/tmp/main.go"]
