#!/usr/bin/env bash
# Cross-builds the openvpn executable for Android arm64 (static OpenSSL). Built for Android (CMake),
# OpenVPN gets TARGET_ANDROID: instead of opening /dev/net/tun it asks the management interface for
# the TUN (OPENTUN etc.), which engine::openvpn answers with the VpnService fd.
#
#   android/openvpn.sh <output file>      (build.sh calls it when its cache has no binary)
set -euo pipefail

OUT_FILE=${1:?output file}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SDK=${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}
NDK=${ANDROID_NDK_ROOT:-$(ls -d "$SDK"/ndk/* | sort -V | tail -1)}
API=26
HOST=aarch64-linux-android

OPENVPN_VERSION=2.7.8
OPENVPN_SHA256=c070d1d2440b5a6fca6c2c68645c98cd492116ac36ef4f0946177115532c8e36
OPENSSL_VERSION=3.5.9
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

WORK=$ROOT/target/android/openvpn-build
CACHE=$ROOT/target/android/cache
mkdir -p "$WORK" "$CACHE"
JOBS=$(nproc)

fetch() { # url sha256 file
    if [[ ! -f $3 ]] || ! echo "$2  $3" | sha256sum -c --quiet 2>/dev/null; then
        echo "==> downloading $1"
        curl -fsSL --retry 3 -o "$3.part" "$1"
        echo "$2  $3.part" | sha256sum -c --quiet || { echo "checksum mismatch: $1" >&2; exit 1; }
        mv "$3.part" "$3"
    fi
}
fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
    $OPENSSL_SHA256 "$CACHE/openssl-$OPENSSL_VERSION.tar.gz"
fetch "https://github.com/OpenVPN/openvpn/releases/download/v$OPENVPN_VERSION/openvpn-$OPENVPN_VERSION.tar.gz" \
    $OPENVPN_SHA256 "$CACHE/openvpn-$OPENVPN_VERSION.tar.gz"

export ANDROID_NDK_ROOT=$NDK
# OpenVPN puts `git describe` in its version; the build dir sits inside this repo.
export GIT_CEILING_DIRECTORIES=$WORK
TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin
export PATH=$TOOLCHAIN:$PATH
PREFIX=$WORK/prefix

# ── OpenSSL: static libssl + libcrypto only ──
if [[ ! -f $PREFIX/lib/libssl.a ]]; then
    echo "==> OpenSSL $OPENSSL_VERSION"
    rm -rf "$WORK/openssl-$OPENSSL_VERSION"
    tar -xzf "$CACHE/openssl-$OPENSSL_VERSION.tar.gz" -C "$WORK"
    (
        cd "$WORK/openssl-$OPENSSL_VERSION"
        ./Configure android-arm64 -D__ANDROID_API__=$API no-shared no-tests no-docs no-apps no-module \
            --prefix="$PREFIX" --libdir=lib >/dev/null
        make -j"$JOBS" build_libs >/dev/null
        make install_dev >/dev/null
    )
fi

# ── OpenVPN: its CMake build is the one that knows Android (TARGET_ANDROID), as ics-openvpn uses ──
echo "==> OpenVPN $OPENVPN_VERSION"
rm -rf "$WORK/openvpn-$OPENVPN_VERSION" "$WORK/openvpn-cmake"
tar -xzf "$CACHE/openvpn-$OPENVPN_VERSION.tar.gz" -C "$WORK"
CMAKE_BIN=$(ls -d "$SDK"/cmake/*/bin | sort -V | tail -1)
# An empty pkg-config path: the desktop's libraries must not leak in.
PKG_CONFIG_LIBDIR=$WORK/no-pkgconfig PKG_CONFIG_PATH= \
"$CMAKE_BIN/cmake" -S "$WORK/openvpn-$OPENVPN_VERSION" -B "$WORK/openvpn-cmake" -G Ninja \
    -DCMAKE_MAKE_PROGRAM="$CMAKE_BIN/ninja" \
    -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=$API -DCMAKE_BUILD_TYPE=Release \
    -DUNSUPPORTED_BUILDS=ON -DUSE_WERROR=OFF -DBUILD_TESTING=OFF \
    -DENABLE_LZ4=OFF -DENABLE_LZO=OFF -DENABLE_PKCS11=OFF -DENABLE_DNS_UPDOWN_BY_DEFAULT=OFF \
    -DOPENSSL_ROOT_DIR="$PREFIX" -DOPENSSL_USE_STATIC_LIBS=ON -Wno-dev -Wno-deprecated >/dev/null
"$CMAKE_BIN/cmake" --build "$WORK/openvpn-cmake" --target openvpn -j"$JOBS" >/dev/null
"$TOOLCHAIN/llvm-strip" -o "$OUT_FILE" "$WORK/openvpn-cmake/openvpn"
echo "==> $OUT_FILE"
