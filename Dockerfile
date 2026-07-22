# syntax=docker/dockerfile:1

# Build stage: compile the static, stripped launcher. CGO off so the result
# links no libc and runs on a distroless/scratch base; -trimpath drops host
# paths for a reproducible build.
FROM golang:1.26 AS build
WORKDIR /src

# Warm the module cache on the manifests alone, so a source-only change
# doesn't re-download dependencies.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /libtunnel ./cmd/libtunnel

# Runtime stage: distroless static with a nonroot user. libtunnel embeds its
# own CA bundle, so no system trust store is needed; the base still supplies
# /etc/passwd, tzdata, and a nonroot uid for least-privilege operation.
FROM gcr.io/distroless/static:nonroot
COPY --from=build /libtunnel /libtunnel
USER nonroot:nonroot

# Configuration is entirely environment (see cmd/libtunnel):
#   docker run --rm \
#     -e LIBTUNNEL__CLOUDFLARE=1 \
#     -e LIBTUNNEL_LOCAL_URL=http://host.docker.internal:8080 \
#     ghcr.io/cnuss/libtunnel
ENTRYPOINT ["/libtunnel"]
