# Build context is the repo root, so the cmd module's `replace => ../../` finds
# the local libtunnel. GOWORK=off keeps the build off the go.work workspace (and
# its chainsaw test module) — only this module's go.mod + replace are used.
FROM golang:1.26 AS build
ENV GOWORK=off CGO_ENABLED=0 GOOS=linux
WORKDIR /src
COPY . .
WORKDIR /src/cmd/ingress-tunnel
RUN go build -o /out/ingress-tunnel .

FROM gcr.io/distroless/static:nonroot
COPY --from=build /out/ingress-tunnel /ingress-tunnel
USER nonroot:nonroot
ENTRYPOINT ["/ingress-tunnel"]
