# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.1-alpine AS build
ARG TARGETOS TARGETARCH
ARG VERSION=0.0.0-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags="-s -w -X github.com/pflege-de-labs/nats-auth-callout/internal/app.Version=${VERSION}" \
    -o /out/nats-auth-callout .

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/nats-auth-callout /nats-auth-callout
USER nonroot:nonroot
EXPOSE 8088
ENTRYPOINT ["/nats-auth-callout"]
