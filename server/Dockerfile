FROM --platform=$BUILDPLATFORM golang:1.26.10-bookworm AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /runtime/wwe2k22-server ./cmd/wwe2k22-server
RUN mkdir -p /runtime/data /runtime/tmp && chmod 1777 /runtime/tmp
COPY licenses/ /runtime/licenses/
FROM scratch
LABEL org.opencontainers.image.title="WWE 2K22 private server (Go)" org.opencontainers.image.version="2026.10.25-server.1"
COPY --from=build --chown=10001:10001 /runtime/ /
USER 10001:10001
ENV WWE_BIND_HOST=0.0.0.0 WWE_STATE_FILE=/data/local-state.sqlite3 WWE_MATCHMAKING=true WWE_CUSTOM_CONTENT=true TMPDIR=/tmp GOMEMLIMIT=384MiB
EXPOSE 8787/tcp 8788/udp
VOLUME ["/data"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/wwe2k22-server"]
