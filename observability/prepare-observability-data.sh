#!/usr/bin/env bash
set -euo pipefail

# Bind-mount ownership is coupled to the runtime UID/GID ABI of each exact
# pinned observability image in compose.yaml. Review the image digest/variant
# and this mapping together. These numeric identities are not host accounts.
readonly EXPECTED_DATA_ROOT=/srv/alert2ir-observability
readonly DATA_DIRECTORY_MODE=0750

fail() {
    printf 'prepare-observability-data: %s\n' "$*" >&2
    exit 1
}

prepare_directory() {
    local service=$1
    local owner=$2
    local group=$3
    local directory="${OBSERVABILITY_DATA_ROOT}/${service}"

    if [[ -L $directory ]]; then
        fail "refusing symbolic-link service directory: ${directory}"
    fi
    if [[ -e $directory && ! -d $directory ]]; then
        fail "service path is not a directory: ${directory}"
    fi

    /usr/bin/install -d -o "$owner" -g "$group" -m "$DATA_DIRECTORY_MODE" -- "$directory"
}

if [[ ! -v OBSERVABILITY_DATA_ROOT ]]; then
    fail 'OBSERVABILITY_DATA_ROOT is required'
fi
if [[ $OBSERVABILITY_DATA_ROOT != "$EXPECTED_DATA_ROOT" ]]; then
    fail "OBSERVABILITY_DATA_ROOT must be exactly ${EXPECTED_DATA_ROOT}"
fi
if [[ -L $OBSERVABILITY_DATA_ROOT ]]; then
    fail "refusing symbolic-link data root: ${OBSERVABILITY_DATA_ROOT}"
fi
if [[ ! -d $OBSERVABILITY_DATA_ROOT ]]; then
    fail "Puppet-owned data root does not exist: ${OBSERVABILITY_DATA_ROOT}"
fi
if [[ $(/usr/bin/readlink -f -- "$OBSERVABILITY_DATA_ROOT") != "$EXPECTED_DATA_ROOT" ]]; then
    fail "data root resolves outside the expected path: ${OBSERVABILITY_DATA_ROOT}"
fi
if (( EUID != 0 )); then
    fail 'must run as root to set numeric bind-directory ownership'
fi

prepare_directory alertmanager 65534 65534
prepare_directory prometheus 65534 65534
prepare_directory grafana 472 0
prepare_directory loki 10001 10001
prepare_directory tempo 10001 10001
