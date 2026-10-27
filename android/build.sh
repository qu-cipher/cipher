#!/usr/bin/env bash
# Builds the Android APK (arm64) straight from the SDK build-tools: no Gradle, no Google Maven.
#
#   android/build.sh            release build of the Rust library (slow: LTO)
#   android/build.sh --debug    faster, unoptimized library
#
# Needs: ANDROID_HOME (platform 36, build-tools 36, an NDK), the aarch64-linux-android Rust target,
# a JDK (javac, keytool), python3, curl. Output: target/android/cipher-<version>-arm64.apk.
#
# Signing: a release key when ANDROID_KEYSTORE is set (with ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS
# and optionally ANDROID_KEY_PASSWORD), else the debug key (~/.android/debug.keystore, created if
# missing). Android only installs an update signed with the same key as the installed app.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
SDK=${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}
NDK=${ANDROID_NDK_ROOT:-$(ls -d "$SDK"/ndk/* | sort -V | tail -1)}
BUILD_TOOLS=$SDK/build-tools/36.0.0
PLATFORM=$SDK/platforms/android-36/android.jar
MIN_SDK=26
TARGET_SDK=36
TARGET=aarch64-linux-android
ABI=arm64-v8a

# Pinned engines (same version as the desktop download, src/engine/install.rs).
SINGBOX_VERSION=1.14.3
SINGBOX_SHA256=149569b5dbf01958e6598beb3a13078d6fc0e353ef06f4aff85f5f28bc23593b

PROFILE=release
[[ ${1:-} == --debug ]] && PROFILE=debug

VERSION=$(grep -m1 '^version' "$ROOT/Cargo.toml" | cut -d'"' -f2)
IFS=. read -r MAJOR MINOR PATCH <<<"$VERSION"
VERSION_CODE=$((MAJOR * 10000 + MINOR * 100 + PATCH))

OUT=$ROOT/target/android
WORK=$OUT/work
CACHE=$OUT/cache
rm -rf "$WORK"
mkdir -p "$WORK/lib/$ABI" "$CACHE"

# ── Rust library ──
CLANG=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
export CC_aarch64_linux_android=$CLANG/$TARGET$MIN_SDK-clang
export AR_aarch64_linux_android=$CLANG/llvm-ar
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=$CLANG/$TARGET$MIN_SDK-clang
cargo_profile=()
[[ $PROFILE == release ]] && cargo_profile=(--release)
echo "==> libcipher_client.so ($PROFILE)"
(cd "$ROOT" && cargo rustc --lib --crate-type cdylib --target $TARGET "${cargo_profile[@]}")
"$CLANG/llvm-strip" -o "$WORK/lib/$ABI/libcipher_client.so" "$ROOT/target/$TARGET/$PROFILE/libcipher_client.so"

# ── Engines: executables, shipped as lib*.so so Android installs and allows running them ──
fetch() { # url sha256 file
    if [[ ! -f $3 ]] || ! echo "$2  $3" | sha256sum -c --quiet 2>/dev/null; then
        echo "==> downloading $1"
        curl -fsSL --retry 3 -o "$3.part" "$1"
        echo "$2  $3.part" | sha256sum -c --quiet || { echo "checksum mismatch: $1" >&2; exit 1; }
        mv "$3.part" "$3"
    fi
}
SINGBOX_TAR=$CACHE/sing-box-$SINGBOX_VERSION-android-arm64.tar.gz
fetch "https://github.com/SagerNet/sing-box/releases/download/v$SINGBOX_VERSION/sing-box-$SINGBOX_VERSION-android-arm64.tar.gz" \
    $SINGBOX_SHA256 "$SINGBOX_TAR"
tar -xzf "$SINGBOX_TAR" -C "$WORK" "sing-box-$SINGBOX_VERSION-android-arm64/sing-box"
mv "$WORK/sing-box-$SINGBOX_VERSION-android-arm64/sing-box" "$WORK/lib/$ABI/libsingbox.so"

# OpenVPN: built from source once (android/openvpn.sh; delete the cached file to rebuild).
OPENVPN_BIN=$CACHE/openvpn-$(grep -m1 '^OPENVPN_VERSION=' "$ROOT/android/openvpn.sh" | cut -d= -f2)-arm64
[[ -f $OPENVPN_BIN ]] || "$ROOT/android/openvpn.sh" "$OPENVPN_BIN"
cp "$OPENVPN_BIN" "$WORK/lib/$ABI/libopenvpn.so"

# ── Java (MainActivity, CipherVpnService) → classes.dex ──
echo "==> java"
mkdir -p "$WORK/classes"
javac --release 17 -nowarn -classpath "$PLATFORM" -d "$WORK/classes" $(find "$ROOT/android/java" -name '*.java')
"$BUILD_TOOLS/d8" --release --min-api $MIN_SDK --lib "$PLATFORM" --output "$WORK" $(find "$WORK/classes" -name '*.class')

# ── Resources + manifest ──
echo "==> apk"
"$BUILD_TOOLS/aapt2" compile --dir "$ROOT/android/res" -o "$WORK/res.zip"
"$BUILD_TOOLS/aapt2" link -o "$WORK/unaligned.apk" -I "$PLATFORM" \
    --manifest "$ROOT/android/AndroidManifest.xml" \
    --min-sdk-version $MIN_SDK --target-sdk-version $TARGET_SDK \
    --version-code $VERSION_CODE --version-name "$VERSION" \
    "$WORK/res.zip"

# Code and native libraries, then align (16 KB pages for .so files) and sign.
python3 -I - "$WORK/unaligned.apk" "$WORK" "lib/$ABI" <<'EOF'
import os, sys, zipfile
apk, work, libdir = sys.argv[1:]
with zipfile.ZipFile(apk, "a", zipfile.ZIP_DEFLATED) as z:
    z.write(os.path.join(work, "classes.dex"), "classes.dex")
    for name in sorted(os.listdir(os.path.join(work, libdir))):
        z.write(os.path.join(work, libdir, name), f"{libdir}/{name}")
EOF
"$BUILD_TOOLS/zipalign" -f -P 16 4 "$WORK/unaligned.apk" "$WORK/aligned.apk"

# Passwords go through the environment, not the command line.
if [[ -n ${ANDROID_KEYSTORE:-} ]]; then
    echo "==> signing with the release key"
    KEYSTORE=$ANDROID_KEYSTORE
    KEY_ALIAS=${ANDROID_KEY_ALIAS:?set ANDROID_KEY_ALIAS}
    export CIPHER_KS_PASS=${ANDROID_KEYSTORE_PASSWORD:?set ANDROID_KEYSTORE_PASSWORD}
    export CIPHER_KEY_PASS=${ANDROID_KEY_PASSWORD:-$CIPHER_KS_PASS}
else
    echo "==> signing with the debug key"
    KEYSTORE=$HOME/.android/debug.keystore
    KEY_ALIAS=androiddebugkey
    export CIPHER_KS_PASS=android CIPHER_KEY_PASS=android
    if [[ ! -f $KEYSTORE ]]; then
        mkdir -p "$(dirname "$KEYSTORE")"
        keytool -genkeypair -keystore "$KEYSTORE" -storepass android -keypass android -alias androiddebugkey \
            -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
    fi
fi
# JDK 22+ warns about apksigner's native crypto unless allowed; older JDKs don't know the flag.
JAVA_FLAGS=()
java_major=$(java -version 2>&1 | sed -nE '1s/.*version "([0-9]+).*/\1/p')
(( ${java_major:-0} >= 22 )) && JAVA_FLAGS=(-J-enable-native-access=ALL-UNNAMED)
APK=$OUT/cipher-$VERSION-arm64.apk
"$BUILD_TOOLS/apksigner" "${JAVA_FLAGS[@]}" sign --ks "$KEYSTORE" --ks-key-alias "$KEY_ALIAS" \
    --ks-pass env:CIPHER_KS_PASS --key-pass env:CIPHER_KEY_PASS \
    --min-sdk-version $MIN_SDK --out "$APK" "$WORK/aligned.apk"
"$BUILD_TOOLS/apksigner" "${JAVA_FLAGS[@]}" verify "$APK"
echo "==> $APK ($(du -h "$APK" | cut -f1))"
