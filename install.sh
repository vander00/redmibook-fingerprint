#!/usr/bin/env bash

set -Eeuo pipefail

readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build/install}"
readonly INSTALL_PREFIX="/usr/local"
readonly SERVICE_NAME="fprintd.service"
readonly SERVICE_DROP_IN="fprintd-fingerprint-ocv.conf"
readonly RELEASE_BASE_URL="https://github.com/vander00/redmibook-fingerprint/releases/latest/download"
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

download_release_binary() {
    local architecture asset url output
    local -a assets

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

    DOWNLOAD_DIR="$(mktemp -d)" || {
        log "Could not create a temporary download directory"
        return 1
    }
    output="${DOWNLOAD_DIR}/fingerprint-ocv"
    assets=("fingerprint-ocv-linux-${architecture}")
    # Keep compatibility with the original unqualified x86-64 asset name.
    if [[ "${architecture}" == x86_64 ]]; then
        assets+=(fingerprint-ocv)
    fi

    for asset in "${assets[@]}"; do
        url="${RELEASE_BASE_URL}/${asset}"
        log "Trying release asset ${asset}"

        if command -v curl >/dev/null 2>&1; then
            curl --fail --location --silent --show-error \
                --output "${output}" "${url}" || continue
        else
            wget --quiet --output-document="${output}" "${url}" || continue
        fi

        if [[ -s "${output}" ]]; then
            RELEASE_BINARY="${output}"
            log "Downloaded ${asset} from the latest GitHub release"
            return 0
        fi
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
                libssl-dev libopencv-dev fprintd
            )
            if [[ "${install_build_tools}" == true ]]; then
                packages+=(build-essential cmake pkg-config git)
            fi
            log "Installing fingerprint packages with apt"
            run_as_root apt-get update
            run_as_root apt-get install -y --no-install-recommends "${packages[@]}"
            ;;
        *" arch "*)
            packages=(usbutils libusb libevent dbus openssl opencv fprintd)
            if [[ "${install_build_tools}" == true ]]; then
                packages+=(base-devel cmake pkgconf git)
            fi
            log "Installing fingerprint packages with pacman"
            run_as_root pacman -S --needed --noconfirm "${packages[@]}"
            ;;
        *" fedora "*|*" rhel "*)
            packages=(
                usbutils libusb1-devel libevent-devel dbus-devel
                openssl-devel opencv-devel fprintd
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
    log "Installed the driver from the latest GitHub release"
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
        -DBUILD_TESTING=OFF \
        -DFINGERPRINT_OCV_USE_VCPKG=OFF

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
