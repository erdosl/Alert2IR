"""Deny networking only in explicitly guarded Sigma subprocesses."""

import os
import socket


if os.environ.get("ALERT2IR_SIGMA_DENY_NETWORK") == "1":
    _MESSAGE = "Alert2IR Sigma subprocess attempted network access"

    def _deny_network(*_args, **_kwargs):
        raise RuntimeError(_MESSAGE)

    socket.getaddrinfo = _deny_network
    socket.create_connection = _deny_network
    socket.socket.connect = _deny_network
    socket.socket.connect_ex = _deny_network
