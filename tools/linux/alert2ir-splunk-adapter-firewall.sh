#!/usr/bin/env bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin

MODE="${1:-check}"
[[ "$#" -le 1 ]] || {
    echo "usage: $0 [apply|check|remove]" >&2
    exit 2
}

readonly EXPECTED_HOST="ir-core"
readonly HOST_ONLY_INTERFACE="enp0s8"
readonly ADAPTER_HOST_IPV4="192.168.56.63"
readonly ADAPTER_HOST_CIDR="192.168.56.63/24"
readonly SPLUNK_IPV4="192.168.56.61"
readonly ADAPTER_PORT="8091"
readonly DOCKER_USER_CHAIN="DOCKER-USER"
readonly ALLOW_COMMENT="alert2ir:splunk-adapter:allow"
readonly DROP_COMMENT="alert2ir:splunk-adapter:drop"

readonly -a IPTABLES=(/usr/sbin/iptables --wait 10)
readonly -a ALLOW_MATCH=(
    -i "${HOST_ONLY_INTERFACE}"
    -s "${SPLUNK_IPV4}/32"
    -p tcp
    -m conntrack
    --ctorigdst "${ADAPTER_HOST_IPV4}"
    --ctorigdstport "${ADAPTER_PORT}"
)
readonly -a DROP_MATCH=(
    -i "${HOST_ONLY_INTERFACE}"
    -p tcp
    -m conntrack
    --ctorigdst "${ADAPTER_HOST_IPV4}"
    --ctorigdstport "${ADAPTER_PORT}"
)
readonly -a ALLOW_RULE=(
    "${ALLOW_MATCH[@]}"
    -m comment --comment "${ALLOW_COMMENT}"
    -j ACCEPT
)
readonly -a DROP_RULE=(
    "${DROP_MATCH[@]}"
    -m comment --comment "${DROP_COMMENT}"
    -j DROP
)
readonly -a LEGACY_ALLOW_RULE=("${ALLOW_MATCH[@]}" -j ACCEPT)
readonly -a LEGACY_DROP_RULE=("${DROP_MATCH[@]}" -j DROP)

die() {
    echo "error: $*" >&2
    exit 1
}

require_root() {
    [[ "${EUID}" -eq 0 ]] || die "run with sudo/root"
}

require_command() {
    command -v "$1" >/dev/null 2>&1 \
        || die "required command is unavailable: $1"
}

assert_host_identity() {
    [[ "$(hostname -s)" == "${EXPECTED_HOST}" ]] \
        || die "host identity is not ${EXPECTED_HOST}"

    local -a addresses=()
    mapfile -t addresses < <(
        ip -4 -o address show dev "${HOST_ONLY_INTERFACE}" scope global \
            | awk '{print $4}'
    )
    [[ "${#addresses[@]}" -eq 1 && "${addresses[0]}" == "${ADAPTER_HOST_CIDR}" ]] \
        || die "${HOST_ONLY_INTERFACE} does not own only ${ADAPTER_HOST_CIDR}"
    ip -4 -brief link show dev "${HOST_ONLY_INTERFACE}" \
        | grep -Eq "^${HOST_ONLY_INTERFACE}[[:space:]]+UP[[:space:]]" \
        || die "${HOST_ONLY_INTERFACE} is not up"
}

assert_iptables_implementation() {
    "${IPTABLES[@]}" --version | grep -Fq '(nf_tables)' \
        || die "expected the iptables nf_tables compatibility implementation"
}

lock_firewall() {
    exec 9>/run/lock/alert2ir-splunk-adapter-firewall.lock
    flock --exclusive 9
}

ensure_docker_user_chain() {
    if ! "${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" >/dev/null 2>&1; then
        "${IPTABLES[@]}" -t filter -N "${DOCKER_USER_CHAIN}"
    fi
}

owned_rule_count() {
    local marker="$1"
    "${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" \
        | awk -v marker="--comment \"${marker}\"" \
            'index($0, marker) { count++ } END { print count + 0 }'
}

remove_owned_rules_below_boundary() {
    local index line total
    total="$(
        "${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" \
            | awk '$1 == "-A" { count++ } END { print count + 0 }'
    )"
    for ((index = total; index >= 3; index--)); do
        line="$("${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" "${index}")"
        if [[ "${line}" == *"--comment \"${ALLOW_COMMENT}\""* \
            || "${line}" == *"--comment \"${DROP_COMMENT}\""* ]]; then
            "${IPTABLES[@]}" -t filter -D "${DOCKER_USER_CHAIN}" "${index}"
        fi
    done
}

remove_all_owned_rules() {
    local index line total
    total="$(
        "${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" \
            | awk '$1 == "-A" { count++ } END { print count + 0 }'
    )"
    for ((index = total; index >= 1; index--)); do
        line="$("${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" "${index}")"
        if [[ "${line}" == *"--comment \"${ALLOW_COMMENT}\""* \
            || "${line}" == *"--comment \"${DROP_COMMENT}\""* ]]; then
            "${IPTABLES[@]}" -t filter -D "${DOCKER_USER_CHAIN}" "${index}"
        fi
    done
}

remove_legacy_rules() {
    while "${IPTABLES[@]}" -t filter -C "${DOCKER_USER_CHAIN}" "${LEGACY_ALLOW_RULE[@]}" 2>/dev/null; do
        "${IPTABLES[@]}" -t filter -D "${DOCKER_USER_CHAIN}" "${LEGACY_ALLOW_RULE[@]}"
    done
    while "${IPTABLES[@]}" -t filter -C "${DOCKER_USER_CHAIN}" "${LEGACY_DROP_RULE[@]}" 2>/dev/null; do
        "${IPTABLES[@]}" -t filter -D "${DOCKER_USER_CHAIN}" "${LEGACY_DROP_RULE[@]}"
    done
}

verify_owned_rules() {
    "${IPTABLES[@]}" -t filter -C "${DOCKER_USER_CHAIN}" "${ALLOW_RULE[@]}" 2>/dev/null \
        || die "the exact Alert2IR allow rule is absent"
    "${IPTABLES[@]}" -t filter -C "${DOCKER_USER_CHAIN}" "${DROP_RULE[@]}" 2>/dev/null \
        || die "the exact Alert2IR drop rule is absent"
    [[ "$(owned_rule_count "${ALLOW_COMMENT}")" -eq 1 ]] \
        || die "the Alert2IR allow rule does not exist exactly once"
    [[ "$(owned_rule_count "${DROP_COMMENT}")" -eq 1 ]] \
        || die "the Alert2IR drop rule does not exist exactly once"

    local first second
    first="$("${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" 1)"
    second="$("${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" 2)"
    [[ "${first}" == *"--comment \"${ALLOW_COMMENT}\""* ]] \
        || die "the Alert2IR allow rule is not first in ${DOCKER_USER_CHAIN}"
    [[ "${second}" == *"--comment \"${DROP_COMMENT}\""* ]] \
        || die "the Alert2IR drop rule is not second in ${DOCKER_USER_CHAIN}"
}

verify_docker_runtime() {
    require_command docker
    local backend first_forward
    backend="$(docker info --format '{{.FirewallBackend.Driver}}')"
    [[ "${backend}" == iptables ]] \
        || die "Docker firewall backend is ${backend:-unknown}, expected iptables"
    first_forward="$("${IPTABLES[@]}" -t filter -S FORWARD 1)"
    [[ "${first_forward}" == '-A FORWARD -j DOCKER-USER' ]] \
        || die "FORWARD does not enter DOCKER-USER before Docker rules"
}

apply_mode() {
    ensure_docker_user_chain

    # Install a fail-closed drop before its matching allow. Existing protection
    # remains in place until the new top pair has been created.
    "${IPTABLES[@]}" -t filter -I "${DOCKER_USER_CHAIN}" 1 "${DROP_RULE[@]}"
    "${IPTABLES[@]}" -t filter -I "${DOCKER_USER_CHAIN}" 1 "${ALLOW_RULE[@]}"

    # Keep the new top pair, remove only older comment-owned copies, then migrate
    # the two exact accepted pre-persistence rules that lacked ownership comments.
    remove_owned_rules_below_boundary
    remove_legacy_rules
    verify_owned_rules
    echo "Alert2IR Splunk adapter firewall boundary applied"
}

check_mode() {
    "${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" >/dev/null 2>&1 \
        || die "${DOCKER_USER_CHAIN} is absent"
    verify_owned_rules
    verify_docker_runtime
    echo "Alert2IR Splunk adapter firewall boundary verified"
}

remove_mode() {
    require_command ss
    if ss -H -lnt '( sport = :8091 )' | grep -q .; then
        die "refusing removal while a TCP 8091 listener is active"
    fi
    if "${IPTABLES[@]}" -t filter -S "${DOCKER_USER_CHAIN}" >/dev/null 2>&1; then
        remove_all_owned_rules
    fi
    echo "Alert2IR-owned Splunk adapter firewall rules removed"
}

require_root
require_command hostname
require_command ip
require_command awk
require_command grep
require_command flock
[[ -x /usr/sbin/iptables ]] || die "required command is unavailable: /usr/sbin/iptables"
assert_host_identity
assert_iptables_implementation
lock_firewall

case "${MODE}" in
    apply) apply_mode ;;
    check) check_mode ;;
    remove) remove_mode ;;
    *) die "unknown mode: ${MODE}" ;;
esac
