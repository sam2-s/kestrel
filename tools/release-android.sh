#!/bin/bash
# Build the Android release artifact and check it:
#   dist/kestrel-<version>.apk  signed universal APK for the GitHub release
#   dist/kestrel.apk            stable name for releases/latest/download/
#
# Gradle signs the build with the checked-in test key (see the signingConfigs
# block in android/app/build.gradle.kts), the same key the Rust alpha under
# app.kestrel.map shipped with, so the two install over each other. Swap that
# block for an environment-held release key before anyone depends on updates
# from this signature: a test key in the repository is a test key for
# everyone.
#
# Never run by CI; CI builds the same APK and uploads it as an artifact.
set -euo pipefail
cd "$(dirname "$0")/.."

SDK="${ANDROID_HOME:-$HOME/Android/Sdk}"

[ -f app/vendor/leaflet/leaflet.js ] || { echo "app/vendor is missing. Run: npm ci && bash tools/sync-vendor.sh"; exit 1; }

echo "== build =="
( cd android && ANDROID_HOME="$SDK" ./gradlew --no-daemon assembleRelease )

VERSION=$(grep -oE 'versionName = "[^"]+"' android/app/build.gradle.kts | cut -d'"' -f2)
mkdir -p dist
APK_IN=android/app/build/outputs/apk/release/app-release.apk
APK_OUT="dist/kestrel-$VERSION.apk"

cp "$APK_IN" "$APK_OUT"
cp "$APK_IN" dist/kestrel.apk

echo "== verify the signature =="
APKSIGNER=$(ls "$SDK"/build-tools/*/apksigner | sort -V | tail -1)
"$APKSIGNER" verify --print-certs "$APK_OUT" | head -4

echo "== artifacts =="
sha256sum "$APK_OUT" dist/kestrel.apk
