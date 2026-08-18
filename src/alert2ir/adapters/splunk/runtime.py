"""Deployment composition for the standalone Splunk source gateway process."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import Mapping
import math
import os
from pathlib import Path
import stat

from fastapi import FastAPI

from alert2ir.adapters.splunk.app import create_splunk_adapter_app
from alert2ir.adapters.splunk.auth import validate_shared_secret
from alert2ir.adapters.splunk.client import (
    DEFAULT_REQUEST_TIMEOUT_SECONDS,
    Alert2IRClient,
)


CORE_URL_ENVIRONMENT_VARIABLE = "ALERT2IR_SPLUNK_ADAPTER_CORE_URL"
SECRET_FILE_ENVIRONMENT_VARIABLE = "ALERT2IR_SPLUNK_ADAPTER_SECRET_FILE"
REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE = (
    "ALERT2IR_SPLUNK_ADAPTER_REQUEST_TIMEOUT_SECONDS"
)
MAXIMUM_SECRET_FILE_BYTES = 4_096


class RuntimeConfigurationError(ValueError):
    """Essential adapter process configuration is missing or invalid."""


def _required_environment_value(
    environment: Mapping[str, str],
    name: str,
) -> str:
    value = environment.get(name)
    if value is None or not value or value != value.strip():
        raise RuntimeConfigurationError(f"{name} is required")
    return value


def _request_timeout(environment: Mapping[str, str]) -> float:
    value = environment.get(
        REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE,
        str(DEFAULT_REQUEST_TIMEOUT_SECONDS),
    )
    try:
        timeout = float(value)
    except (TypeError, ValueError) as error:
        raise RuntimeConfigurationError(
            f"{REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE} must be a finite positive number"
        ) from error
    if not math.isfinite(timeout) or timeout <= 0:
        raise RuntimeConfigurationError(
            f"{REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE} must be a finite positive number"
        )
    return timeout


def _load_shared_secret(path_text: str) -> bytes:
    path = Path(path_text)
    if not path.is_absolute():
        raise RuntimeConfigurationError("shared secret file path must be absolute")

    try:
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeConfigurationError(
                "shared secret file must be a readable regular file"
            )
        if metadata.st_size > MAXIMUM_SECRET_FILE_BYTES + 2:
            raise RuntimeConfigurationError("shared secret file is too large")
        with path.open("rb") as source:
            secret = source.read(MAXIMUM_SECRET_FILE_BYTES + 2)
    except RuntimeConfigurationError:
        raise
    except OSError as error:
        raise RuntimeConfigurationError("shared secret file is not readable") from error

    if secret.endswith(b"\r\n"):
        secret = secret[:-2]
    elif secret.endswith(b"\n"):
        secret = secret[:-1]
    if len(secret) > MAXIMUM_SECRET_FILE_BYTES:
        raise RuntimeConfigurationError("shared secret file is too large")
    try:
        return validate_shared_secret(secret)
    except ValueError as error:
        raise RuntimeConfigurationError(
            "shared secret file must contain at least 32 bytes"
        ) from error


def create_splunk_adapter_app_from_environment(
    environment: Mapping[str, str] | None = None,
) -> FastAPI:
    """Build the process app or fail before Uvicorn reports it healthy."""

    configured_environment = os.environ if environment is None else environment
    core_url = _required_environment_value(
        configured_environment,
        CORE_URL_ENVIRONMENT_VARIABLE,
    )
    secret_path = _required_environment_value(
        configured_environment,
        SECRET_FILE_ENVIRONMENT_VARIABLE,
    )
    timeout = _request_timeout(configured_environment)
    shared_secret = _load_shared_secret(secret_path)

    try:
        client = Alert2IRClient(base_url=core_url, timeout_seconds=timeout)
    except ValueError as error:
        raise RuntimeConfigurationError(
            f"{CORE_URL_ENVIRONMENT_VARIABLE} must be an HTTP(S) origin"
        ) from error

    app = create_splunk_adapter_app(
        shared_secret=shared_secret,
        alert2ir_client=client,
    )
    base_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        async with base_lifespan(application):
            try:
                yield
            finally:
                await client.aclose()

    app.router.lifespan_context = lifespan
    return app


__all__ = [
    "CORE_URL_ENVIRONMENT_VARIABLE",
    "REQUEST_TIMEOUT_ENVIRONMENT_VARIABLE",
    "SECRET_FILE_ENVIRONMENT_VARIABLE",
    "RuntimeConfigurationError",
    "create_splunk_adapter_app_from_environment",
]
