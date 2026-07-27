#!/usr/bin/env bash
#
# Cross-compile passauf for Android and drop the results where Gradle expects
# them (app/src/main/jniLibs/<abi>/libpassauf.so).
#
# This talks to the NDK directly rather than going through cargo-ndk, so the
# only thing you need installed is the NDK itself and the Rust targets. Gradle
# runs it before every build; you can also run it by hand.
#
# Usage: build-rust.sh [--debug] [abi ...]
#   abi defaults to every ABI listed in ABIS below.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate_root="$(dirname "$here")"
jni_libs="$here/app/src/main/jniLibs"

# API 26 (Android 8.0) is the oldest the app supports. It has to match minSdk in
# app/build.gradle.kts: the NDK stamps the level into the binary.
API_LEVEL=26

# arm64 covers essentially every phone in use; armeabi-v7a is there for older
# hardware, and x86_64 for the emulator. Nothing ships an x86 phone with NFC.
ABIS=(arm64-v8a armeabi-v7a x86_64)

profile=release
cargo_profile_flag=(--release)
if [[ "${1:-}" == "--debug" ]]; then
    profile=debug
    cargo_profile_flag=()
    shift
fi
if [[ $# -gt 0 ]]; then
    ABIS=("$@")
fi

# The NDK can be pointed at directly, or found under the SDK.
ndk="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
if [[ -z "$ndk" ]]; then
    sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
    if [[ -d "$sdk/ndk" ]]; then
        # Newest installed version wins.
        ndk="$sdk/ndk/$(ls -1 "$sdk/ndk" | sort -V | tail -1)"
    fi
fi
if [[ ! -d "$ndk" ]]; then
    echo "Could not find the Android NDK." >&2
    echo "Install it (Android Studio: SDK Manager > SDK Tools > NDK) or set ANDROID_NDK_HOME." >&2
    exit 1
fi

host_tag="linux-x86_64"
case "$(uname -s)" in
    Darwin) host_tag="darwin-x86_64" ;;
esac
toolchain="$ndk/toolchains/llvm/prebuilt/$host_tag/bin"
if [[ ! -d "$toolchain" ]]; then
    echo "The NDK at $ndk has no prebuilt toolchain for $host_tag." >&2
    exit 1
fi

# The ABI names Android uses, the target triples Rust uses, and the prefix the
# NDK's clang wrappers are named after. armeabi-v7a is the odd one out: its
# triple and its tool prefix disagree.
triple_for() {
    case "$1" in
        arm64-v8a) echo "aarch64-linux-android" ;;
        armeabi-v7a) echo "armv7-linux-androideabi" ;;
        x86_64) echo "x86_64-linux-android" ;;
        x86) echo "i686-linux-android" ;;
        *) echo "Unknown ABI: $1" >&2; exit 1 ;;
    esac
}

tool_prefix_for() {
    case "$1" in
        armeabi-v7a) echo "armv7a-linux-androideabi" ;;
        *) triple_for "$1" ;;
    esac
}

for abi in "${ABIS[@]}"; do
    triple="$(triple_for "$abi")"
    tool_prefix="$(tool_prefix_for "$abi")"
    clang="$toolchain/${tool_prefix}${API_LEVEL}-clang"

    if [[ ! -x "$clang" ]]; then
        echo "No compiler for $abi at $clang." >&2
        echo "The NDK may be too old for API level $API_LEVEL." >&2
        exit 1
    fi
    if ! rustup target list --installed | grep -qx "$triple"; then
        echo "Rust target $triple is missing. Adding it." >&2
        rustup target add "$triple"
    fi

    # Cargo reads the linker from an env var named after the target, shouting.
    triple_env="$(echo "$triple" | tr '[:lower:]-' '[:upper:]_')"
    echo "Building passauf for $abi ($triple, $profile)"
    env \
        "CARGO_TARGET_${triple_env}_LINKER=$clang" \
        "CC_${triple}=$clang" \
        "AR_${triple}=$toolchain/llvm-ar" \
        cargo build \
            --manifest-path "$crate_root/Cargo.toml" \
            --target "$triple" \
            "${cargo_profile_flag[@]}" \
            --no-default-features \
            --features android

    mkdir -p "$jni_libs/$abi"
    cp "$crate_root/target/$triple/$profile/libpassauf.so" "$jni_libs/$abi/libpassauf.so"
done

echo "Wrote libpassauf.so for: ${ABIS[*]}"
