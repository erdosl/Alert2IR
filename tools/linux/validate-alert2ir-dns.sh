#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-repository}"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
CONFIG_ROOT="${REPOSITORY_ROOT}/config/dns"
ZONE_NAME="alert2ir.test"

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "required command is unavailable: $1" >&2
        exit 1
    }
}

validate_static_semantics() {
    local top_file="$1"
    local options_file="$2"
    local local_file="$3"
    local zone_file="$4"

    grep -Eq 'listen-on[[:space:]]*\{[[:space:]]*192\.168\.56\.64;[[:space:]]*\};' "${options_file}"
    grep -Eq 'listen-on-v6[[:space:]]*\{[[:space:]]*none;[[:space:]]*\};' "${options_file}"
    grep -Eq 'recursion[[:space:]]+no;' "${options_file}"
    grep -Eq 'allow-recursion[[:space:]]*\{[[:space:]]*none;[[:space:]]*\};' "${options_file}"
    grep -Eq 'allow-query-cache[[:space:]]*\{[[:space:]]*none;[[:space:]]*\};' "${options_file}"
    grep -Eq 'session-keyfile[[:space:]]+none;' "${options_file}"
    grep -Eq 'controls[[:space:]]*\{[[:space:]]*\};' "${top_file}"
    ! grep -Eqi 'forwarders|forward[[:space:]]+(first|only)' "${options_file}" "${local_file}"
    grep -Eq 'zone[[:space:]]+"alert2ir\.test"' "${local_file}"
    grep -Eq 'allow-update[[:space:]]*\{[[:space:]]*none;[[:space:]]*\};' "${local_file}"
    grep -Eq 'allow-transfer[[:space:]]*\{[[:space:]]*none;[[:space:]]*\};' "${local_file}"
    ! grep -Eq '(^|[[:space:]])(AAAA|PTR|CNAME)([[:space:]]|$)' "${zone_file}"
    ! grep -Eq '(^|[[:space:]])\*([[:space:]]|\.)' "${zone_file}"
}

require_command named-checkconf
require_command named-checkzone

case "${MODE}" in
    repository)
        STAGE_ROOT="$(mktemp -d --tmpdir alert2ir-dns-validate.XXXXXXXX)"
        trap 'rm -rf -- "${STAGE_ROOT}"' EXIT
        install -d -m 0755 \
            "${STAGE_ROOT}/etc/bind/alert2ir/zones" \
            "${STAGE_ROOT}/var/cache/bind"
        sed "s#/etc/bind/alert2ir#${STAGE_ROOT}/etc/bind/alert2ir#g" \
            "${CONFIG_ROOT}/named.conf.alert2ir" >"${STAGE_ROOT}/etc/bind/alert2ir/named.conf"
        # named.conf declares directory "/var/cache/bind"; map that runtime
        # directory to its counterpart inside the synthetic filesystem.
        sed "s#/var/cache/bind#${STAGE_ROOT}/var/cache/bind#g" \
            "${CONFIG_ROOT}/named.conf.options.alert2ir" >"${STAGE_ROOT}/etc/bind/alert2ir/named.conf.options"
        sed "s#/etc/bind/alert2ir#${STAGE_ROOT}/etc/bind/alert2ir#g" \
            "${CONFIG_ROOT}/named.conf.local.alert2ir" >"${STAGE_ROOT}/etc/bind/alert2ir/named.conf.local"
        install -m 0644 "${CONFIG_ROOT}/zones/db.alert2ir.test" "${STAGE_ROOT}/etc/bind/alert2ir/zones/db.alert2ir.test"
        named-checkconf "${STAGE_ROOT}/etc/bind/alert2ir/named.conf"
        named-checkzone "${ZONE_NAME}" "${CONFIG_ROOT}/zones/db.alert2ir.test"
        validate_static_semantics \
            "${CONFIG_ROOT}/named.conf.alert2ir" \
            "${CONFIG_ROOT}/named.conf.options.alert2ir" \
            "${CONFIG_ROOT}/named.conf.local.alert2ir" \
            "${CONFIG_ROOT}/zones/db.alert2ir.test"
        ;;
    deployed)
        named-checkconf /etc/bind/alert2ir/named.conf
        named-checkzone "${ZONE_NAME}" /etc/bind/alert2ir/zones/db.alert2ir.test
        validate_static_semantics \
            /etc/bind/alert2ir/named.conf \
            /etc/bind/alert2ir/named.conf.options \
            /etc/bind/alert2ir/named.conf.local \
            /etc/bind/alert2ir/zones/db.alert2ir.test
        ;;
    *)
        echo "usage: $0 [repository|deployed]" >&2
        exit 2
        ;;
esac

echo "Alert2IR DNS ${MODE} validation passed"
