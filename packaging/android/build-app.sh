#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Builds the NanoChronometer Android app: the JNI library for all four ABIs,
# then the APK, signed for release.
#
# No Gradle. The app is one Java source tree and a manifest, and the SDK's own
# tools build it directly: aapt2 (resources), javac, d8 (dex), zipalign,
# apksigner. That keeps the build offline and reproducible, and leaves the
# user's Gradle cache alone.
#
# Usage:
#   packaging/android/build-app.sh                  # all ABIs, release-signed
#   packaging/android/build-app.sh arm64-v8a x86_64 # some ABIs
#
# Environment:
#   ANDROID_HOME     SDK (default: ~/Android/Sdk)
#   ANDROID_NDK_HOME NDK (default: the newest under $ANDROID_HOME/ndk)
#   RUST_BIN         a nightly toolchain's bin/ (default: whatever `cargo` is).
#                    Nightly is needed only for an ABI whose standard library
#                    is not installed: it is then built from rust-src.
#   KEYSTORE_PROPERTIES  signing config (default:
#                    packaging/android/keystore/keystore.properties), with
#                    storeFile, storePassword, keyAlias, keyPassword. Absent:
#                    the APK is signed with the SDK debug key and says so.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
app="${repo_root}/packaging/android/app"
out="${repo_root}/dist/android-app"
work="${repo_root}/target/android-app"

sdk="${ANDROID_HOME:-${HOME}/Android/Sdk}"
ndk="${ANDROID_NDK_HOME:-$(ls -d "${sdk}"/ndk/*/ 2>/dev/null | sort -V | tail -1)}"
ndk="${ndk%/}"
build_tools="$(ls -d "${sdk}"/build-tools/*/ | sort -V | tail -1)"
build_tools="${build_tools%/}"
compile_sdk=36
platform_jar="${sdk}/platforms/android-${compile_sdk}/android.jar"
min_api=23
ndk_api=21

for f in "${platform_jar}" "${build_tools}/aapt2" "${build_tools}/d8" "${ndk}/source.properties"; do
    [[ -e "${f}" ]] || { echo "error: missing ${f}" >&2; exit 1; }
done
if [[ -n "${RUST_BIN:-}" ]]; then
    export PATH="${RUST_BIN}:${PATH}"
fi

bin="${ndk}/toolchains/llvm/prebuilt/linux-x86_64/bin"
declare -A rust_target=(
    [arm64-v8a]=aarch64-linux-android
    [armeabi-v7a]=armv7-linux-androideabi
    [x86_64]=x86_64-linux-android
    [x86]=i686-linux-android
)
declare -A clang_prefix=(
    [arm64-v8a]=aarch64-linux-android
    [armeabi-v7a]=armv7a-linux-androideabi
    [x86_64]=x86_64-linux-android
    [x86]=i686-linux-android
)

abis=("$@")
[[ ${#abis[@]} -eq 0 ]] && abis=(arm64-v8a armeabi-v7a x86_64 x86)

rm -rf "${work}/apk" "${work}/classes" "${work}/res" "${work}/dex"
mkdir -p "${work}/apk/lib" "${work}/classes" "${work}/res" "${work}/dex" "${out}"

# --- 1. the JNI library, per ABI -------------------------------------------
sysroot="$(rustc --print sysroot)"
for abi in "${abis[@]}"; do
    target="${rust_target[${abi}]:?unknown ABI ${abi}}"
    cc="${bin}/${clang_prefix[${abi}]}${ndk_api}-clang"
    linker_var="CARGO_TARGET_$(echo "${target}" | tr 'a-z-' 'A-Z_')_LINKER"
    extra=()
    # No prebuilt standard library for this target: build it from source.
    if [[ ! -d "${sysroot}/lib/rustlib/${target}" ]]; then
        extra=(-Zbuild-std=std,panic_abort)
        echo "=== ${abi}: no prebuilt std for ${target}; building it from rust-src"
    fi
    echo "=== ${abi} (${target})"
    env "${linker_var}=${cc}" "CC_${target}=${cc}" \
        "AR_${target}=${bin}/llvm-ar" "RANLIB_${target}=${bin}/llvm-ranlib" \
        cargo build --profile dist --target "${target}" "${extra[@]}" \
            --manifest-path "${repo_root}/Cargo.toml" \
            --target-dir "${work}/cargo" \
            -p nanochrono-android
    mkdir -p "${work}/apk/lib/${abi}"
    "${bin}/llvm-strip" --strip-unneeded \
        -o "${work}/apk/lib/${abi}/libnanochrono_jni.so" \
        "${work}/cargo/${target}/dist/libnanochrono_jni.so"
done

# --- 2. resources and manifest ---------------------------------------------
version_name="$(sed -n 's/^version = "\(.*\)"/\1/p' "${repo_root}/Cargo.toml" | head -1)"
"${build_tools}/aapt2" compile --dir "${app}/res" -o "${work}/res/res.zip"
"${build_tools}/aapt2" link \
    -I "${platform_jar}" \
    --manifest "${app}/AndroidManifest.xml" \
    --min-sdk-version "${min_api}" --target-sdk-version "${compile_sdk}" \
    --version-code "$(echo "${version_name}" | awk -F. '{print $1*10000+$2*100+$3}')" \
    --version-name "${version_name}" \
    --java "${work}/gen" \
    -o "${work}/base.apk" \
    "${work}/res/res.zip"

# --- 3. Java -> dex --------------------------------------------------------
find "${app}/java" "${work}/gen" -name '*.java' > "${work}/sources.txt"
javac -source 8 -target 8 -Xlint:-options -encoding UTF-8 \
    -bootclasspath "${platform_jar}:${build_tools}/core-lambda-stubs.jar" \
    -d "${work}/classes" @"${work}/sources.txt"
"${build_tools}/d8" --release --min-api "${min_api}" --lib "${platform_jar}" \
    --output "${work}/dex" $(find "${work}/classes" -name '*.class')

# --- 4. assemble, align, sign ----------------------------------------------
command cp -f "${work}/base.apk" "${work}/unsigned.apk"
(cd "${work}/dex" && zip -q -X "${work}/unsigned.apk" classes.dex)
# Native libraries stored uncompressed and page-aligned, so the loader maps
# them straight out of the APK (extractNativeLibs=false).
(cd "${work}/apk" && zip -q -X -0 -r "${work}/unsigned.apk" lib)
"${build_tools}/zipalign" -f -P 16 4 "${work}/unsigned.apk" "${work}/aligned.apk"

props="${KEYSTORE_PROPERTIES:-${repo_root}/packaging/android/keystore/keystore.properties}"
apk="${out}/nanochronometer-${version_name}.apk"
if [[ -f "${props}" ]]; then
    prop() { sed -n "s/^$1=//p" "${props}" | head -1; }
    store="$(prop storeFile)"
    [[ "${store}" = /* ]] || store="$(dirname "${props}")/${store}"
    "${build_tools}/apksigner" sign \
        --ks "${store}" --ks-key-alias "$(prop keyAlias)" \
        --ks-pass "pass:$(prop storePassword)" --key-pass "pass:$(prop keyPassword)" \
        --out "${apk}" "${work}/aligned.apk"
    echo "signed for release with ${store}"
else
    apk="${out}/nanochronometer-${version_name}-debug.apk"
    "${build_tools}/apksigner" sign --ks "${HOME}/.android/debug.keystore" \
        --ks-pass pass:android --key-pass pass:android \
        --out "${apk}" "${work}/aligned.apk"
    echo "WARNING: no ${props}; signed with the debug key"
fi
"${build_tools}/apksigner" verify --print-certs "${apk}" | head -3
echo "=== ${apk}"
