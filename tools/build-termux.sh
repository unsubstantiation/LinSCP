#!/usr/bin/env bash
# Termux CLI build for Android (aarch64-linux-android)
# Respects $TMPDIR (Termux uses $PREFIX/tmp) and termux-open-url for --open-browser.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo not found – install rustup" >&2
  exit 1
fi

# Ensure Android targets are installed
rustup target add aarch64-linux-android x86_64-linux-android armv7-linux-androideabi 2>/dev/null || true

# Resolve Android NDK for cargo-ndk
if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -d /usr/local/lib/android/sdk/ndk ]; then
  export ANDROID_NDK_HOME="$(ls -d /usr/local/lib/android/sdk/ndk/* | sort -V | tail -n 1)"
fi

if [ -n "${ANDROID_NDK_HOME:-}" ] && command -v cargo-ndk >/dev/null 2>&1; then
  echo "Building Termux linscp via cargo ndk for aarch64-linux-android..."
  # Headless / Termux build respects $TMPDIR – ensure it is set to a writable path
  export TMPDIR="${TMPDIR:-/tmp}"
  cargo ndk -t arm64-v8a build --release -p linscp-cli
  echo "Termux build complete: target/aarch64-linux-android/release/linscp"
else
  echo "cargo-ndk or ANDROID_NDK_HOME not available – falling back to cargo check"
  cargo check --target aarch64-linux-android -p linscp-cli
  echo "Termux check passed (no NDK build)"
fi

# Verify termux-open-url handling is compiled in (android target)
echo "Verifying termux-open-url launcher in gui_os..."
if grep -q "termux-open-url" "$REPO_ROOT/crates/linscp-platform/src/gui_os.rs"; then
  echo "termux-open-url support verified"
else
  echo "termux-open-url string missing – check gui_os.rs" >&2
  exit 1
fi
