# Author: Domonick Mack
# Date: 2026-11-16
# Description: Multi-stage production Dockerfile for the Doom SIEM Go backend engine.

FROM golang:1.23-alpine AS builder

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /app/bin/doom-server ./cmd/server

FROM alpine:3.20

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata wget && \
    addgroup -S doom && adduser -S doom -G doom

COPY --from=builder /app/bin/doom-server /app/doom-server

USER doom

EXPOSE 8080 5514/udp 5514/tcp

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8080/api/v1/health || exit 1

ENTRYPOINT ["/app/doom-server"]
