# APKCheck Lab — multi-arch image (linux/amd64 primary; Apple Silicon via buildx).
#
#   docker buildx build --platform linux/amd64 -t apkcheck:0.1 --load .
#   docker compose up -d lab

ARG GO_IMAGE=golang:1.27-bookworm
ARG NODE_IMAGE=node:22-bookworm-slim
ARG RUNTIME_IMAGE=eclipse-temurin:17-jdk-jammy
ARG TARGETPLATFORM=linux/amd64
ARG TARGETOS=linux
ARG TARGETARCH=amd64

# ---------- UI (native build platform — faster on Apple Silicon) ----------
FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS ui
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# ---------- CLI (cross-compile GOOS/GOARCH for TARGETPLATFORM) ----------
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
# Image already ships Go 1.27 — avoid proxy toolchain download under QEMU.
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=ui /src/web/dist ./web/dist
RUN mkdir -p bin \
 && go build -trimpath -ldflags="-s -w" -o bin/apkcheck ./cmd/apkcheck

# ---------- Runtime (platform set by compose / buildx --platform) ----------
FROM ${RUNTIME_IMAGE} AS runtime

LABEL org.opencontainers.image.title="apkcheck" \
      org.opencontainers.image.description="APKCheck Lab — Android security workbench v0.1" \
      org.apkcheck.component="lab"

ENV DEBIAN_FRONTEND=noninteractive \
    ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    PATH="/opt/apkcheck:/opt/android-sdk/platform-tools:/opt/jadx/bin:${PATH}" \
    APKCHECK_LAB_WORKSPACE=/data/lab \
    APKTOOL_VERSION=2.11.1 \
    JADX_VERSION=1.5.0 \
    PLATFORM_TOOLS_VERSION=35.0.2

# Emulator binary (host-mounted SDK) needs a few X11/GL stubs even with -no-window.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip git \
      netcat-openbsd \
      libx11-6 libxext6 libxrender1 libxi6 libxrandr2 libxfixes3 \
      libnss3 libnspr4 libxcb1 libxkbcommon0 libgl1 \
    && rm -rf /var/lib/apt/lists/*

# apktool
RUN mkdir -p /opt/apktool \
 && curl -fsSL -o /opt/apktool/apktool.jar \
      "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
 && printf '%s\n' '#!/bin/sh' 'exec java -jar /opt/apktool/apktool.jar "$@"' > /usr/local/bin/apktool \
 && chmod +x /usr/local/bin/apktool

# jadx (retry — GitHub releases can flake under QEMU/amd64)
RUN set -eux; \
    for i in 1 2 3 4 5; do \
      curl -fL --retry 3 --retry-delay 2 -o /tmp/jadx.zip \
        "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" \
        && break; \
      sleep $((i * 3)); \
    done; \
    test -s /tmp/jadx.zip; \
    unzip -q /tmp/jadx.zip -d /opt/jadx; \
    rm /tmp/jadx.zip; \
    chmod +x /opt/jadx/bin/jadx; \
    test -x /opt/jadx/bin/jadx

# Android platform-tools (adb) — linux x86_64
RUN mkdir -p "${ANDROID_HOME}" \
 && curl -fsSL -o /tmp/platform-tools.zip \
      "https://dl.google.com/android/repository/platform-tools-latest-linux.zip" \
 && unzip -q /tmp/platform-tools.zip -d "${ANDROID_HOME}" \
 && rm /tmp/platform-tools.zip

WORKDIR /opt/apkcheck
COPY --from=build /src/bin/apkcheck /opt/apkcheck/apkcheck
COPY --from=ui /src/web/dist /opt/apkcheck/web/dist
COPY configs /opt/apkcheck/configs
COPY docs /opt/apkcheck/docs

RUN mkdir -p /data/lab \
 && useradd --create-home --uid 10001 --shell /usr/sbin/nologin apkcheck \
 && chown -R apkcheck:apkcheck /data/lab /opt/apkcheck

USER apkcheck
WORKDIR /data/lab
EXPOSE 8787

# Default: Lab UI (API + React). Override for CLI/MCP:
#   docker run ... apkcheck lab validate ...
#   docker run -i ... apkcheck mcp
ENTRYPOINT ["/opt/apkcheck/apkcheck"]
CMD ["lab", "ui", "--workspace", "/data/lab", "--ui", "/opt/apkcheck/web/dist", "--addr", ":8787", "--no-open"]
