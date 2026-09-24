# Build ATDE catcher image
FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o /atde ./cmd/atde

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates iptables ipset \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /atde /app/atde
COPY configs/config.yaml /app/configs/config.yaml
RUN mkdir -p /app/data/caught /app/data/evidence /app/data/sandbox
ENV NATS_URL=nats://nats:4222
ENV ATDE_LIVE=1
EXPOSE 8080 2222 2323 6379 8443 9080 9091
ENTRYPOINT ["/app/atde", "-config", "/app/configs/config.yaml", "-mode", "catch-node"]
