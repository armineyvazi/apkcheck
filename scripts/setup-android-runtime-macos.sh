#!/usr/bin/env bash
# Setup macOS Android runtime for apkcheck (emulator path).
# Physical USB phones only need: brew install android-platform-tools + USB debugging.
set -euo pipefail

export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home}"
export ANDROID_HOME="${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export PATH="$JAVA_HOME/bin:$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$PATH"
export SKIP_JDK_VERSION_CHECK=true

echo "==> ANDROID_HOME=$ANDROID_HOME"
echo "==> host arch=$(uname -m)"

if [[ ! -x "$JAVA_HOME/bin/java" ]]; then
  echo "Install JDK 17+: brew install openjdk@17"
  exit 1
fi

if ! command -v sdkmanager >/dev/null; then
  echo "Install cmdline-tools: brew install --cask android-commandlinetools"
  exit 1
fi

yes | sdkmanager --licenses >/dev/null || true

sdkmanager --install \
  "platform-tools" \
  "emulator" \
  "platforms;android-34" \
  "system-images;android-34;google_apis;arm64-v8a"

AVD_NAME="${1:-Pixel_8_API_34}"
if ! avdmanager list avd 2>/dev/null | grep -q "$AVD_NAME"; then
  echo "no" | avdmanager create avd -n "$AVD_NAME" \
    -k "system-images;android-34;google_apis;arm64-v8a" \
    -d pixel_8 || true
fi

echo
echo "Done. Next:"
echo "  export ANDROID_HOME=$ANDROID_HOME"
echo "  export ANDROID_SDK_ROOT=\$ANDROID_HOME"
echo "  apkcheck emulators"
echo "  apkcheck runtime app.apk --emulator $AVD_NAME --screenshots"
echo
echo "Physical phone:"
echo "  connect USB-C → enable USB debugging → apkcheck devices"
echo "  apkcheck runtime app.apk --device-id <ID>"
