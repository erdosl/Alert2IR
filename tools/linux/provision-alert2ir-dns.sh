#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-check}"
shift || true

REMOVE_MANAGEMENT_RULE=false
ALTERNATE_MANAGEMENT_VERIFIED=false
PURGE_PACKAGES=false
DRY_RUN=false
for argument in "$@"; do
    case "${argument}" in
        --remove-management-rule) REMOVE_MANAGEMENT_RULE=true ;;
        --alternate-management-verified) ALTERNATE_MANAGEMENT_VERIFIED=true ;;
        --purge-packages) PURGE_PACKAGES=true ;;
        --dry-run) DRY_RUN=true ;;
        *) echo "unknown argument: ${argument}" >&2; exit 2 ;;
    esac
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPOSITORY_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
CONFIG_ROOT="${REPOSITORY_ROOT}/config/dns"
CONTRACT_PATH="${CONFIG_ROOT}/alert2ir-dns.json"
DEPLOY_ROOT="/etc/bind/alert2ir"
STATE_ROOT="/var/lib/alert2ir-dns"
PRESTATE_ROOT="${STATE_ROOT}/prestate-initial"
OVERRIDE_NAME="alert2ir.conf"

SERVER_HOST="dev01"
SERVER_IPV4="192.168.56.64"
SERVER_INTERFACE="enp0s8"
NAT_IPV4="10.0.2.15"
MANAGEMENT_IPV4="192.168.56.1"

die() {
    echo "error: $*" >&2
    exit 1
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "run with sudo/root"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

contract_rows() {
    python3 - "${CONTRACT_PATH}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    contract = json.load(stream)

management = contract["firewall"]["management"]
print("management\t{source_ipv4}\t{destination_ipv4}\t{interface}\t{protocol}\t{destination_port}\t{comment}".format(**management))
for rule in contract["firewall"]["dns"]:
    print("dns\t{source_ipv4}\t{destination_ipv4}\t{interface}\t{protocol}\t{destination_port}\t{comment}".format(**rule))
PY
}

assert_contract_identity() {
    python3 - "${CONTRACT_PATH}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    value = json.load(stream)
assert value["server"] == {
    "host": "dev01",
    "ipv4": "192.168.56.64",
    "interface": "enp0s8",
    "nat_ipv4": "10.0.2.15",
    "listeners": {"ipv4": ["192.168.56.64"], "ipv6": []},
}
assert value["firewall"]["management"]["source_ipv4"] == "192.168.56.1"
assert [client["ipv4"] for client in value["clients"]] == ["192.168.56.60", "192.168.56.62"]
PY
}

assert_host_identity() {
    [[ "$(hostname)" == "${SERVER_HOST}" ]] || die "host identity is not ${SERVER_HOST}"
    ip -4 -brief address show dev "${SERVER_INTERFACE}" | grep -Eq "^${SERVER_INTERFACE}[[:space:]]+UP[[:space:]]+${SERVER_IPV4}/24([[:space:]]|$)" \
        || die "${SERVER_INTERFACE} does not own ${SERVER_IPV4}/24"
    ip -4 -brief address show dev enp0s3 | grep -Eq "^enp0s3[[:space:]]+UP[[:space:]]+${NAT_IPV4}/24([[:space:]]|$)" \
        || die "enp0s3 does not own expected NAT address ${NAT_IPV4}/24"
}

assert_management_session() {
    ss -Htn state established '( sport = :22 )' | grep -Eq "${SERVER_IPV4}:22[[:space:]]+${MANAGEMENT_IPV4}:[0-9]+" \
        || die "no established ${MANAGEMENT_IPV4} -> ${SERVER_IPV4}:22 management session"
}

port_53_conflict_check() {
    local lines
    lines="$(ss -H -lntup '( sport = :53 )')"
    if [[ -z "${lines}" ]]; then
        return
    fi
    if grep -Fq 'named' <<<"${lines}"; then
        return
    fi
    if grep -Ev '127\.0\.0\.(53|54)(%lo)?:53' <<<"${lines}" | grep -q .; then
        die "unexpected non-systemd-resolved listener conflicts with port 53"
    fi
}

discover_service_unit() {
    local candidate unit fragment
    for candidate in bind9.service named.service; do
        unit="$(systemctl show --property=Id --value "${candidate}" 2>/dev/null || true)"
        fragment="$(systemctl show --property=FragmentPath --value "${candidate}" 2>/dev/null || true)"
        if [[ -n "${unit}" && -n "${fragment}" ]]; then
            printf '%s\n' "${unit}"
            return
        fi
    done
    die "package-provided BIND service unit was not found"
}

capture_prestate() {
    if [[ -d "${PRESTATE_ROOT}" ]]; then
        return
    fi
    install -d -m 0700 "${PRESTATE_ROOT}/bind-files"
    hostname >"${PRESTATE_ROOT}/hostname.txt"
    cp -a /etc/os-release "${PRESTATE_ROOT}/os-release"
    ip -brief address >"${PRESTATE_ROOT}/ip-address.txt"
    ip route >"${PRESTATE_ROOT}/ip-route.txt"
    ss -lntup >"${PRESTATE_ROOT}/listeners.txt"
    readlink -f /etc/resolv.conf >"${PRESTATE_ROOT}/resolv-conf-link.txt"
    cp -a /etc/resolv.conf "${PRESTATE_ROOT}/resolv.conf"
    systemctl is-active systemd-resolved >"${PRESTATE_ROOT}/systemd-resolved-active.txt" || true
    systemctl is-enabled systemd-resolved >"${PRESTATE_ROOT}/systemd-resolved-enabled.txt" || true
    systemctl list-unit-files >"${PRESTATE_ROOT}/unit-files.txt"
    dpkg-query -W 'bind9*' >"${PRESTATE_ROOT}/bind-packages.txt" 2>&1 || true
    ufw status numbered >"${PRESTATE_ROOT}/ufw-status-numbered.txt"
    ufw show added >"${PRESTATE_ROOT}/ufw-show-added.txt"
    ss -Htn state established '( sport = :22 )' >"${PRESTATE_ROOT}/ssh-sessions.txt"
    for path in /etc/bind/named.conf /etc/bind/named.conf.options /etc/bind/named.conf.local; do
        if [[ -e "${path}" ]]; then
            cp -a "${path}" "${PRESTATE_ROOT}/bind-files/$(basename "${path}")"
            sha256sum "${path}" >>"${PRESTATE_ROOT}/bind-file-hashes.txt"
        fi
    done
    if dpkg-query -W -f='${Status}' bind9 2>/dev/null | grep -Fqx 'install ok installed'; then
        printf 'false\n' >"${PRESTATE_ROOT}/bind9-installed-by-alert2ir.txt"
    else
        printf 'true\n' >"${PRESTATE_ROOT}/bind9-installed-by-alert2ir.txt"
    fi
    if ufw status | grep -Fqx 'Status: active'; then
        printf 'active\n' >"${PRESTATE_ROOT}/ufw-observed-state.txt"
    else
        printf 'inactive\n' >"${PRESTATE_ROOT}/ufw-observed-state.txt"
    fi
    chmod -R go-rwx "${PRESTATE_ROOT}"
}

install_bind_packages() {
    if dpkg-query -W -f='${Status}' bind9 2>/dev/null | grep -Fqx 'install ok installed'; then
        return
    fi

    local policy_created=false policy_temp
    if [[ ! -e /usr/sbin/policy-rc.d ]]; then
        policy_temp="$(mktemp --tmpdir alert2ir-policy-rc.XXXXXXXX)"
        printf '#!/bin/sh\nexit 101\n' >"${policy_temp}"
        install -o root -g root -m 0755 "${policy_temp}" /usr/sbin/policy-rc.d
        rm -f -- "${policy_temp}"
        policy_created=true
    fi

    cleanup_policy_rc() {
        if [[ "${policy_created}" == true ]]; then
            rm -f -- /usr/sbin/policy-rc.d
        fi
    }
    trap cleanup_policy_rc RETURN
    DEBIAN_FRONTEND=noninteractive apt-get install --yes bind9 bind9-utils
    cleanup_policy_rc
    trap - RETURN
}

stage_configuration() {
    local service_unit="$1" override_directory
    install -d -o root -g bind -m 0750 "${DEPLOY_ROOT}/zones"
    install -o root -g bind -m 0640 "${CONFIG_ROOT}/named.conf.alert2ir" "${DEPLOY_ROOT}/named.conf"
    install -o root -g bind -m 0640 "${CONFIG_ROOT}/named.conf.options.alert2ir" "${DEPLOY_ROOT}/named.conf.options"
    install -o root -g bind -m 0640 "${CONFIG_ROOT}/named.conf.local.alert2ir" "${DEPLOY_ROOT}/named.conf.local"
    install -o root -g bind -m 0640 "${CONFIG_ROOT}/zones/db.alert2ir.test" "${DEPLOY_ROOT}/zones/db.alert2ir.test"

    override_directory="/etc/systemd/system/${service_unit}.d"
    install -d -o root -g root -m 0755 "${override_directory}"
    install -o root -g root -m 0644 "${CONFIG_ROOT}/alert2ir-systemd-override.conf" "${override_directory}/${OVERRIDE_NAME}"
    systemctl daemon-reload
}

ufw_line_for_comment() {
    local comment="$1"
    ufw show added | grep -F "comment '${comment}'" || true
}

assert_stored_ufw_rule() {
    local source="$1" destination="$2" interface="$3" protocol="$4" port="$5" comment="$6"
    local line count
    line="$(ufw_line_for_comment "${comment}")"
    count="$(grep -c . <<<"${line}" || true)"
    [[ "${count}" -eq 1 ]] || die "expected exactly one stored UFW rule with comment: ${comment}"
    [[ "${line}" == *"allow in"* ]] || die "UFW rule is not inbound allow: ${comment}"
    [[ "${line}" == *"on ${interface}"* ]] || die "UFW interface mismatch: ${comment}"
    [[ "${line}" == *"from ${source}"* ]] || die "UFW source mismatch: ${comment}"
    [[ "${line}" == *"to ${destination}"* ]] || die "UFW destination mismatch: ${comment}"
    [[ "${line}" == *"port ${port}"* ]] || die "UFW port mismatch: ${comment}"
    [[ "${line}" == *"proto ${protocol}"* ]] || die "UFW protocol mismatch: ${comment}"
}

ensure_ufw_rule() {
    local source="$1" destination="$2" interface="$3" protocol="$4" port="$5" comment="$6"
    local existing
    existing="$(ufw_line_for_comment "${comment}")"
    if [[ -z "${existing}" ]]; then
        ufw allow in on "${interface}" from "${source}" to "${destination}" port "${port}" proto "${protocol}" comment "${comment}"
    fi
    assert_stored_ufw_rule "${source}" "${destination}" "${interface}" "${protocol}" "${port}" "${comment}"
}

assert_complete_ufw_contract() {
    local kind source destination interface protocol port comment
    local expected_count=0 actual_count
    while IFS=$'\t' read -r kind source destination interface protocol port comment; do
        assert_stored_ufw_rule "${source}" "${destination}" "${interface}" "${protocol}" "${port}" "${comment}"
        expected_count=$((expected_count + 1))
    done < <(contract_rows)

    actual_count="$(ufw show added | grep -c '^ufw ' || true)"
    [[ "${actual_count}" -eq "${expected_count}" ]] \
        || die "stored UFW policy has ${actual_count} rules; expected exactly ${expected_count}"
    grep -Fqx 'DEFAULT_INPUT_POLICY="DROP"' /etc/default/ufw || die "UFW default incoming policy is not DROP"
    ! ufw show added | grep -Eq 'enp0s3|from (any|0\.0\.0\.0/0)|192\.168\.56\.0/24' \
        || die "stored UFW policy contains a broad or NAT-interface rule"
}

stage_firewall() {
    local kind source destination interface protocol port comment
    local first=true
    while IFS=$'\t' read -r kind source destination interface protocol port comment; do
        if [[ "${first}" == true && "${kind}" != management ]]; then
            die "management UFW rule must be first in the contract"
        fi
        ensure_ufw_rule "${source}" "${destination}" "${interface}" "${protocol}" "${port}" "${comment}"
        first=false
    done < <(contract_rows)

    assert_complete_ufw_contract
}

enable_firewall() {
    assert_complete_ufw_contract
    if ! ufw status | grep -Fqx 'Status: active'; then
        assert_management_session
        ufw --force enable
    fi
    ufw status | grep -Fqx 'Status: active' || die "UFW did not become active"
    assert_management_session
    assert_complete_ufw_contract
}

configure_firewall() {
    stage_firewall
    enable_firewall
}

assert_listener_contract() {
    local named_lines
    named_lines="$(ss -H -lntup '( sport = :53 )' | grep -F 'named' || true)"
    grep -Eq "udp[[:space:]].*${SERVER_IPV4}:53" <<<"${named_lines}" || die "BIND UDP listener is missing"
    grep -Eq "tcp[[:space:]].*${SERVER_IPV4}:53" <<<"${named_lines}" || die "BIND TCP listener is missing"
    ! grep -Eq '0\.0\.0\.0:53|10\.0\.2\.15:53|127\.0\.0\.1:53|172\.17\.0\.1:53|\[::\]:53|\*:[[:space:]]*53' <<<"${named_lines}" \
        || die "BIND has a prohibited listener"
    [[ "$(grep -c . <<<"${named_lines}" || true)" -eq 2 ]] || die "BIND has an unexpected number of port 53 listeners"
}

assert_resolved_contract() {
    systemctl is-active --quiet systemd-resolved || die "systemd-resolved is not active"
    local resolved_lines
    resolved_lines="$(ss -H -lntup '( sport = :53 )' | grep -F 'systemd-resolve' || true)"
    grep -Eq '127\.0\.0\.53(%lo)?:53' <<<"${resolved_lines}" || die "systemd-resolved .53 stub is missing"
    grep -Eq '127\.0\.0\.54:53' <<<"${resolved_lines}" || die "systemd-resolved .54 proxy is missing"
}

check_hashes() {
    local failed=false
    declare -A pairs=(
        ["${CONFIG_ROOT}/named.conf.alert2ir"]="${DEPLOY_ROOT}/named.conf"
        ["${CONFIG_ROOT}/named.conf.options.alert2ir"]="${DEPLOY_ROOT}/named.conf.options"
        ["${CONFIG_ROOT}/named.conf.local.alert2ir"]="${DEPLOY_ROOT}/named.conf.local"
        ["${CONFIG_ROOT}/zones/db.alert2ir.test"]="${DEPLOY_ROOT}/zones/db.alert2ir.test"
    )
    local source deployed
    for source in "${!pairs[@]}"; do
        deployed="${pairs[${source}]}"
        if [[ ! -f "${deployed}" ]] || ! cmp -s "${source}" "${deployed}"; then
            echo "hash mismatch or absent: ${deployed}" >&2
            failed=true
        else
            sha256sum "${source}" "${deployed}"
        fi
    done
    [[ "${failed}" == false ]]
}

check_mode() {
    local failed=false service_unit=""
    assert_contract_identity || failed=true
    assert_host_identity || failed=true
    port_53_conflict_check || failed=true
    dpkg-query -W -f='${binary:Package}\t${Version}\n' bind9 bind9-utils bind9-dnsutils 2>/dev/null || failed=true
    if dpkg-query -W -f='${Status}' bind9 2>/dev/null | grep -Fqx 'install ok installed'; then
        service_unit="$(discover_service_unit)"
        echo "service_unit=${service_unit}"
        systemctl is-active --quiet "${service_unit}" || failed=true
        systemctl is-enabled --quiet "${service_unit}" || failed=true
        "${SCRIPT_DIR}/validate-alert2ir-dns.sh" deployed || failed=true
        check_hashes || failed=true
        assert_listener_contract || failed=true
        assert_resolved_contract || failed=true
    else
        echo "bind9 is not installed" >&2
        failed=true
    fi
    ufw status | grep -Fqx 'Status: active' || failed=true
    assert_complete_ufw_contract || failed=true
    [[ "${failed}" == false ]] || return 1
    echo "Alert2IR DNS check passed"
}

apply_mode() {
    assert_contract_identity
    assert_host_identity
    assert_management_session
    port_53_conflict_check
    capture_prestate
    install_bind_packages

    local service_unit
    service_unit="$(discover_service_unit)"
    if systemctl is-active --quiet "${service_unit}" && [[ ! -f "/etc/systemd/system/${service_unit}.d/${OVERRIDE_NAME}" ]]; then
        die "BIND became active before Alert2IR static validation"
    fi

    stage_configuration "${service_unit}"
    "${SCRIPT_DIR}/validate-alert2ir-dns.sh" deployed
    configure_firewall
    systemctl enable "${service_unit}"
    if systemctl is-active --quiet "${service_unit}"; then
        systemctl restart "${service_unit}"
    else
        systemctl start "${service_unit}"
    fi
    systemctl is-active --quiet "${service_unit}" || die "BIND service is not active"
    systemctl is-enabled --quiet "${service_unit}" || die "BIND service is not enabled"
    journalctl -u "${service_unit}" --since '-2 minutes' --no-pager | grep -Eqi '(^|[^a-z])(error|fatal|failed)([^a-z]|$)' \
        && die "recent BIND journal contains an error" || true
    assert_listener_contract
    assert_resolved_contract
    check_hashes
    printf '%s\n' "${service_unit}" >"${STATE_ROOT}/service-unit.txt"
    chmod 0600 "${STATE_ROOT}/service-unit.txt"
    check_mode
}

delete_exact_ufw_rule() {
    local source="$1" destination="$2" interface="$3" protocol="$4" port="$5" comment="$6"
    local existing
    existing="$(ufw_line_for_comment "${comment}")"
    if [[ -z "${existing}" ]]; then
        return
    fi
    assert_stored_ufw_rule "${source}" "${destination}" "${interface}" "${protocol}" "${port}" "${comment}"
    ufw --force delete allow in on "${interface}" from "${source}" to "${destination}" port "${port}" proto "${protocol}" comment "${comment}"
}

remove_mode() {
    [[ "${REMOVE_MANAGEMENT_RULE}" == false || "${ALTERNATE_MANAGEMENT_VERIFIED}" == true ]] \
        || die "management-rule removal requires --alternate-management-verified"

    local service_unit=""
    if [[ -f "${STATE_ROOT}/service-unit.txt" ]]; then
        service_unit="$(<"${STATE_ROOT}/service-unit.txt")"
    elif dpkg-query -W -f='${Status}' bind9 2>/dev/null | grep -Fqx 'install ok installed'; then
        service_unit="$(discover_service_unit)"
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        [[ -n "${service_unit}" ]] || die "service identity is unavailable"
        [[ -f "/etc/systemd/system/${service_unit}.d/${OVERRIDE_NAME}" ]] || die "owned systemd drop-in is absent"
        [[ -d "${DEPLOY_ROOT}" ]] || die "owned BIND deployment is absent"
        local dry_kind dry_source dry_destination dry_interface dry_protocol dry_port dry_comment
        while IFS=$'\t' read -r dry_kind dry_source dry_destination dry_interface dry_protocol dry_port dry_comment; do
            if [[ "${dry_kind}" == management && "${REMOVE_MANAGEMENT_RULE}" == false ]]; then
                echo "retain exact UFW rule: ${dry_comment}"
                continue
            fi
            assert_stored_ufw_rule "${dry_source}" "${dry_destination}" "${dry_interface}" "${dry_protocol}" "${dry_port}" "${dry_comment}"
            echo "would remove exact UFW rule: ${dry_comment}"
        done < <(contract_rows)
        echo "would stop/disable ${service_unit}, remove ${DEPLOY_ROOT}, and remove only the owned systemd drop-in"
        if [[ "${PURGE_PACKAGES}" == true ]]; then
            [[ -f "${PRESTATE_ROOT}/bind9-installed-by-alert2ir.txt" ]] || die "package ownership state is unavailable"
            [[ "$(<"${PRESTATE_ROOT}/bind9-installed-by-alert2ir.txt")" == true ]] || die "refusing to purge pre-existing BIND packages"
            echo "would purge Alert2IR-installed bind9 and bind9-utils packages"
        fi
        return
    fi

    if [[ -n "${service_unit}" ]]; then
        systemctl disable --now "${service_unit}" || true
        rm -f -- "/etc/systemd/system/${service_unit}.d/${OVERRIDE_NAME}"
        rmdir --ignore-fail-on-non-empty "/etc/systemd/system/${service_unit}.d" 2>/dev/null || true
        systemctl daemon-reload
    fi
    rm -rf -- "${DEPLOY_ROOT}"

    local kind source destination interface protocol port comment
    while IFS=$'\t' read -r kind source destination interface protocol port comment; do
        if [[ "${kind}" == management && "${REMOVE_MANAGEMENT_RULE}" == false ]]; then
            continue
        fi
        delete_exact_ufw_rule "${source}" "${destination}" "${interface}" "${protocol}" "${port}" "${comment}"
    done < <(contract_rows)

    if [[ "${PURGE_PACKAGES}" == true ]]; then
        [[ -f "${PRESTATE_ROOT}/bind9-installed-by-alert2ir.txt" ]] || die "package ownership state is unavailable"
        [[ "$(<"${PRESTATE_ROOT}/bind9-installed-by-alert2ir.txt")" == true ]] || die "refusing to purge pre-existing BIND packages"
        DEBIAN_FRONTEND=noninteractive apt-get purge --yes bind9 bind9-utils
    fi
    if [[ "${REMOVE_MANAGEMENT_RULE}" == true ]]; then
        echo "Alert2IR DNS-owned state removed; management rule retained=false"
    else
        echo "Alert2IR DNS-owned state removed; management rule retained=true"
    fi
}

require_root
require_command python3
require_command ip
require_command ss
require_command ufw

case "${MODE}" in
    check) check_mode ;;
    apply) apply_mode ;;
    firewall-stage)
        assert_contract_identity
        assert_host_identity
        assert_management_session
        capture_prestate
        stage_firewall
        ufw show added
        ;;
    firewall-enable)
        assert_contract_identity
        assert_host_identity
        assert_management_session
        enable_firewall
        ufw status verbose
        ufw status numbered
        ;;
    remove) remove_mode ;;
    *) echo "usage: $0 {check|apply|firewall-stage|firewall-enable|remove} [--dry-run] [--remove-management-rule --alternate-management-verified] [--purge-packages]" >&2; exit 2 ;;
esac
