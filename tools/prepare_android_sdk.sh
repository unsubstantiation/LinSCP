#!/usr/bin/env bash
set -euxo pipefail
sdk=${ANDROID_SDK_ROOT:-${ANDROID_HOME:-}}
if [ -z "$sdk" ]; then echo 'Android SDK location is not configured' >&2; exit 1; fi
ndk=$(ls -d "$sdk"/ndk/* | sort -V | tail -n 1)
echo "ANDROID_HOME=$sdk" >> "$GITHUB_ENV"
echo "ANDROID_SDK_ROOT=$sdk" >> "$GITHUB_ENV"
echo "NDK_HOME=$ndk" >> "$GITHUB_ENV"
yes | "$sdk/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null || true
"$sdk/cmdline-tools/latest/bin/sdkmanager" "platforms;android-36" "build-tools;36.0.0"
