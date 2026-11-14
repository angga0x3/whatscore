# syntax=docker/dockerfile:1
#
# Multi-stage build: compile a static binary with the Go toolchain, ship it
# in a distroless runtime image (no shell, no package manager, non-root).

ARG GO_VERSION=1.25.11

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS build
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=bind,source=go.mod,target=go.mod \
    --mount=type=bind,source=go.sum,target=go.sum \
    go mod download

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
        -o /out/whatscore ./cmd/whatscore

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/whatscore /whatscore

USER nonroot:nonroot
EXPOSE 8080

ENTRYPOINT ["/whatscore"]
