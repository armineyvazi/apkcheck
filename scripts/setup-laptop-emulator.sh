#!/usr/bin/env bash
# Install Android SDK emulator + Pixel_8_API_34 AVD on the Linux Lab laptop (host).
# The Lab Docker container only ships adb — the emulator must run on the host (needs /dev/kvm).
#
# Usage (on armin@13.0.0.216 or via ssh):
#   ./scripts/setup-laptop-emulator.sh
#   ./scripts/setup-laptop-emulator.sh --start
set -euo pipefail

SDK_ROOT="${ANDROID_HOME:-$HOME/Android/Sdk}"
AVD_NAME="${AVD_NAME:-Pixel_8_API_34}"
API=34
IMG="system-images;android-${API};google_apis;x86_64"
CMDLINE_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"

if [[ ! -e /dev/kvm ]]; then
  echo "ERROR: /dev/kvm missing — enable KVM / nested virt on this host" >&2
  exit 1
fi

PORTABLE_JDK="${PORTABLE_JDK:-$HOME/.local/jdk-17}"
if ! command -v java >/dev/null 2>&1 && [[ ! -x "$PORTABLE_JDK/bin/java" ]]; then
  echo "== download portable Temurin JDK 17 (no sudo) =="
  mkdir -p "$HOME/.local"
  tmp=$(mktemp -d)
  curl -fL --retry 3 -o "$tmp/jdk17.tgz" \
    "https://api.adoptium.net/v3/binary/latest/17/ga/linux/x64/jdk/hotspot/normal/eclipse?project=jdk"
  tar -xzf "$tmp/jdk17.tgz" -C "$tmp"
  rm -rf "$PORTABLE_JDK"
  mv "$tmp"/jdk-17* "$PORTABLE_JDK"
  rm -rf "$tmp"
fi
if [[ -x "$PORTABLE_JDK/bin/java" ]]; then
  export JAVA_HOME="$PORTABLE_JDK"
elif command -v java >/dev/null 2>&1; then
  export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
else
  echo "ERROR: install a JDK and re-run (java not found)" >&2
  exit 1
fi
export PATH="$JAVA_HOME/bin:$PATH"
echo "JAVA_HOME=$JAVA_HOME"

mkdir -p "$SDK_ROOT/cmdline-tools"
export ANDROID_HOME="$SDK_ROOT"
export ANDROID_SDK_ROOT="$SDK_ROOT"
export PATH="$SDK_ROOT/cmdline-tools/latest/bin:$SDK_ROOT/emulator:$SDK_ROOT/platform-tools:$PATH"

if [[ ! -x "$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager" ]]; then
  echo "== download cmdline-tools =="
  tmp=$(mktemp -d)
  curl -fL --retry 3 -o "$tmp/cmdtools.zip" "$CMDLINE_URL"
  unzip -q "$tmp/cmdtools.zip" -d "$tmp"
  rm -rf "$SDK_ROOT/cmdline-tools/latest"
  mkdir -p "$SDK_ROOT/cmdline-tools/latest"
  mv "$tmp/cmdline-tools"/* "$SDK_ROOT/cmdline-tools/latest/"
  rm -rf "$tmp"
fi

yes | sdkmanager --licenses >/dev/null || true
echo "== sdkmanager packages =="
sdkmanager --install \
  "platform-tools" \
  "emulator" \
  "platforms;android-${API}" \
  "$IMG"

echo "== create AVD ${AVD_NAME} =="
if ! avdmanager list avd 2>/dev/null | grep -q "Name: ${AVD_NAME}"; then
  # Device profiles differ by cmdline-tools version; fall back if pixel_8 missing.
  if avdmanager list device 2>/dev/null | grep -qiE 'pixel[_ ]?8|id:[[:space:]]*pixel_8'; then
    echo "no" | avdmanager create avd -n "$AVD_NAME" -k "$IMG" -d pixel_8 --force
  else
    echo "no" | avdmanager create avd -n "$AVD_NAME" -k "$IMG" --force
  fi
fi

# Headless-friendly defaults
ini="$HOME/.android/avd/${AVD_NAME}.avd/config.ini"
if [[ -f "$ini" ]]; then
  grep -q '^hw.keyboard=' "$ini" || echo 'hw.keyboard=yes' >>"$ini"
  grep -q '^hw.gpu.enabled=' "$ini" || echo 'hw.gpu.enabled=yes' >>"$ini"
  grep -q '^hw.gpu.mode=' "$ini" || echo 'hw.gpu.mode=auto' >>"$ini"
fi

echo "SDK_ROOT=$SDK_ROOT"
echo "AVD=$AVD_NAME"
"$SDK_ROOT/emulator/emulator" -list-avds || true
adb version | head -1

if [[ "${1:-}" == "--start" ]]; then
  echo "== cold-boot ${AVD_NAME} =="
  nohup "$SDK_ROOT/emulator/emulator" -avd "$AVD_NAME" -no-window -no-audio -no-boot-anim -gpu auto \
    >/tmp/apkcheck-emulator.log 2>&1 &
  echo "emulator pid $! · log /tmp/apkcheck-emulator.log"
  adb wait-for-device
  for i in $(seq 1 90); do
    boot=$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')
    [[ "$boot" == "1" ]] && break
    sleep 2
  done
  adb devices -l
fi

echo "OK — Lab container (network_mode:host) will see emulator via adb on this host."
echo "Mount SDK into Lab: ANDROID_HOME=$SDK_ROOT (see docker-compose.yml)"
