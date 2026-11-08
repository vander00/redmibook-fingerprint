#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build/install}"
readonly INSTALL_PREFIX="/usr/local"
readonly SERVICE_NAME="fprintd.service"
readonly SERVICE_DROP_IN="fprintd-fingerprint-ocv.conf"
readonly RELEASE_REPO_URL="https://github.com/vander00/redmibook-fingerprint/releases"
# Optional: pin a release tag (e.g. v2.1). Defaults to the latest release.
readonly RELEASE_VERSION="${RELEASE_VERSION:-}"
# Optional: expected SHA-256 of the binary. Defaults to the digest published
# beside the asset as <asset>.sha256 in the same release.
readonly RELEASE_SHA256="${RELEASE_SHA256:-}"
DOWNLOAD_DIR=""
RELEASE_BINARY=""

log() {
    printf '==> %s\n' "$*"
}

die() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

run_as_root() {
    if (( EUID == 0 )); then
        "$@"
    else
        command -v sudo >/dev/null 2>&1 || die "sudo is required to install system packages and files"
        sudo "$@"
    fi
}

cleanup() {
    if [[ -n "${DOWNLOAD_DIR}" && -d "${DOWNLOAD_DIR}" ]]; then
        rm -rf -- "${DOWNLOAD_DIR}"
    fi
}

fetch() {
    local url="$1" output="$2"

    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \
            --output "${output}" "${url}"
    else
        wget --quiet --https-only --output-document="${output}" "${url}"
    fi
}

download_release_binary() {
    local architecture asset url output base_url release_label expected checksum_file
    local -a assets

    if [[ -n "${RELEASE_SHA256}" && ! "${RELEASE_SHA256}" =~ ^[[:xdigit:]]{64}$ ]]; then
        die "RELEASE_SHA256 must be a 64-character hexadecimal SHA-256 digest"
    fi

    if [[ -n "${RELEASE_VERSION}" ]]; then
        base_url="${RELEASE_REPO_URL}/download/${RELEASE_VERSION}"
        release_label="release ${RELEASE_VERSION}"
    else
        base_url="${RELEASE_REPO_URL}/latest/download"
        release_label="the latest GitHub release"
    fi

    case "$(uname -m)" in
        x86_64|amd64) architecture="x86_64" ;;
        aarch64|arm64) architecture="aarch64" ;;
        *)
            log "No release binary is available for architecture $(uname -m)"
            return 1
            ;;
    esac

    if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
        log "Neither curl nor wget is available; building from source"
        return 1
    fi

    if ! command -v sha256sum >/dev/null 2>&1; then
        log "sha256sum is not available to verify the release binary; building from source"
        return 1
    fi

    DOWNLOAD_DIR="$(mktemp -d)" || {
        log "Could not create a temporary download directory"
        return 1
    }
    output="${DOWNLOAD_DIR}/fingerprint-ocv"
    checksum_file="${DOWNLOAD_DIR}/fingerprint-ocv.sha256"
    assets=("fingerprint-ocv-linux-${architecture}")
    # Keep compatibility with the original unqualified x86-64 asset name.
    if [[ "${architecture}" == x86_64 ]]; then
        assets+=(fingerprint-ocv)
    fi

    for asset in "${assets[@]}"; do
        url="${base_url}/${asset}"
        log "Trying release asset ${asset} from ${release_label}"

        fetch "${url}" "${output}" 2>/dev/null || continue
        [[ -s "${output}" ]] || continue

        if [[ -n "${RELEASE_SHA256}" ]]; then
            expected="${RELEASE_SHA256}"
        else
            if ! fetch "${url}.sha256" "${checksum_file}" 2>/dev/null; then
                rm -f -- "${output}"
                log "No published checksum (${asset}.sha256) in ${release_label}; refusing the unverified binary and building from source"
                return 1
            fi
            # The checksum file uses sha256sum format: "<digest>  <name>".
            read -r expected _ < "${checksum_file}" || true
            if [[ ! "${expected}" =~ ^[[:xdigit:]]{64}$ ]]; then
                rm -f -- "${output}"
                log "Malformed checksum file for ${asset}; refusing the unverified binary and building from source"
                return 1
            fi
        fi

        if ! printf '%s  %s\n' "${expected,,}" "${output}" | sha256sum --check --status -; then
            rm -f -- "${output}"
            die "SHA-256 verification failed for ${asset} from ${release_label}; the download may be corrupted or tampered with"
        fi

        RELEASE_BINARY="${output}"
        log "Downloaded ${asset} from ${release_label} and verified SHA-256 ${expected,,}"
        return 0
    done

    log "No compatible release binary was found; building from source"
    return 1
}

install_dependencies() {
    local install_build_tools="${1:-false}"
    local -a packages

    [[ -r /etc/os-release ]] || die "cannot identify this Linux distribution"

    # shellcheck disable=SC1091
    . /etc/os-release
    local distro="${ID:-} ${ID_LIKE:-}"

    case " ${distro} " in
        *" debian "*|*" ubuntu "*)
            packages=(
                usbutils libusb-1.0-0-dev libevent-dev libdbus-1-dev
                libssl-dev fprintd
            )
            if [[ "${install_build_tools}" == true ]]; then
                packages+=(build-essential cmake pkg-config git)
            fi
            log "Installing fingerprint packages with apt"
            run_as_root apt-get update
            run_as_root apt-get install -y --no-install-recommends "${packages[@]}"
            ;;
        *" arch "*)
            packages=(usbutils libusb libevent dbus openssl fprintd)
            if [[ "${install_build_tools}" == true ]]; then
                packages+=(base-devel cmake pkgconf git)
            fi
            log "Installing fingerprint packages with pacman"
            run_as_root pacman -S --needed --noconfirm "${packages[@]}"
            ;;
        *" fedora "*|*" rhel "*)
            packages=(
                usbutils libusb1-devel libevent-devel dbus-devel
                openssl-devel fprintd
            )
            if [[ "${install_build_tools}" == true ]]; then
                packages+=(gcc-c++ make cmake pkgconf-pkg-config git)
            fi
            log "Installing fingerprint packages with dnf"
            run_as_root dnf install -y "${packages[@]}"
            ;;
        *)
            die "unsupported distribution '${ID:-unknown}'; install the dependencies from README.md manually"
            ;;
    esac
}

[[ "$(uname -s)" == "Linux" ]] || die "this driver only supports Linux"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
trap cleanup EXIT

download_release_binary || true

if [[ -n "${RELEASE_BINARY}" ]]; then
    install_dependencies false
    run_as_root install -Dm755 "${RELEASE_BINARY}" \
        "${INSTALL_PREFIX}/bin/fingerprint-ocv"
    log "Installed the verified release binary"
else
    install_dependencies true
    [[ -f "${SCRIPT_DIR}/CMakeLists.txt" ]] || die "run this script from a complete source checkout"

    log "Fetching source dependencies"
    git -C "${SCRIPT_DIR}" submodule sync -- asyncdbus asyncusb jinx
    git -C "${SCRIPT_DIR}" submodule update --init --recursive asyncdbus asyncusb jinx

    log "Configuring a release build"
    cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" \
        -DCMAKE_C_COMPILER=gcc \
        -DCMAKE_CXX_COMPILER=g++ \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=OFF

    log "Building the driver"
    cmake --build "${BUILD_DIR}" --parallel

    log "Installing the locally built driver"
    run_as_root cmake --install "${BUILD_DIR}" --prefix "${INSTALL_PREFIX}"
fi

log "Installing the system service override"
run_as_root install -Dm644 \
    "${SCRIPT_DIR}/${SERVICE_DROP_IN}" \
    "/etc/systemd/system/${SERVICE_NAME}.d/20-fingerprint-ocv.conf"

# Disable the legacy standalone unit when upgrading.  Running behind the
# standard fprintd unit preserves D-Bus activation and prevents another
# provider from taking net.reactivated.Fprint during a restart.
run_as_root systemctl disable --now fingerprint-ocv.service 2>/dev/null || true
run_as_root systemctl daemon-reload
run_as_root systemctl restart "${SERVICE_NAME}"

if ! run_as_root systemctl is-active --quiet "${SERVICE_NAME}"; then
    run_as_root journalctl -u "${SERVICE_NAME}" -n 30 --no-pager || true
    die "the service failed to start; see the log above"
fi

log "Installation complete"
printf '%s\n' \
    "Enroll a finger with: fprintd-enroll" \
    "Check the service with: systemctl status ${SERVICE_NAME}"
