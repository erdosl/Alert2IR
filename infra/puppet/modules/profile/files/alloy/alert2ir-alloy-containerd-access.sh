#!/usr/bin/env bash
set -euo pipefail

readonly SOCKET_PATH=/run/containerd/containerd.sock
readonly ACCESS_GROUP=alloy-containerd

usage() {
  echo "Usage: $0 <check|apply>" >&2
}

check_access() {
  if ! /usr/bin/getent group "$ACCESS_GROUP" >/dev/null; then
    echo "Error: required group '$ACCESS_GROUP' does not exist." >&2
    return 1
  fi
  if [[ ! -S $SOCKET_PATH ]]; then
    echo "Error: '$SOCKET_PATH' is not a Unix socket." >&2
    return 1
  fi

  local current_group current_mode
  current_group=$(/usr/bin/stat -c '%G' -- "$SOCKET_PATH")
  current_mode=$(/usr/bin/stat -c '%a' -- "$SOCKET_PATH")
  if [[ $current_group != "$ACCESS_GROUP" || $current_mode != 660 ]]; then
    echo "Error: '$SOCKET_PATH' must be group '$ACCESS_GROUP' with mode 0660." >&2
    return 1
  fi
}

if (( $# != 1 )); then
  usage
  exit 2
fi

case $1 in
  check)
    check_access
    ;;
  apply)
    if ! /usr/bin/getent group "$ACCESS_GROUP" >/dev/null; then
      echo "Error: required group '$ACCESS_GROUP' does not exist." >&2
      exit 1
    fi
    if [[ ! -S $SOCKET_PATH ]]; then
      echo "Error: '$SOCKET_PATH' is not a Unix socket." >&2
      exit 1
    fi
    /usr/bin/chgrp -- "$ACCESS_GROUP" "$SOCKET_PATH"
    /usr/bin/chmod -- 0660 "$SOCKET_PATH"
    check_access
    ;;
  *)
    usage
    exit 2
    ;;
esac
