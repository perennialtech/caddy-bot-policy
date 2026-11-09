FROM --platform=$BUILDPLATFORM caddy:2.11.9-builder AS builder
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum *.go ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH xcaddy build --with github.com/perennialtech/caddy-turnstile=.

FROM caddy:2.11.9
COPY --from=builder /src/caddy /usr/bin/caddy
