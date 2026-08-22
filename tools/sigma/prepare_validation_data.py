#!/usr/bin/env python3
"""Download, verify, and cache Alert2IR's pinned Sigma validation data."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


SCHEMA = "alert2ir.sigma-validation-data.v1"
ATTACK_REPOSITORY = "mitre-attack/attack-stix-data"
ATTACK_PATH = "enterprise-attack/enterprise-attack.json"
ATTACK_FILENAME = "enterprise-attack.json"
D3FEND_FILENAME = "d3fend.json"
DOWNLOAD_ATTEMPTS = 3
HTTP_TIMEOUT_SECONDS = 30
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]

_TOP_LEVEL_FIELDS = frozenset({"schema", "datasets"})
_DATASET_FIELDS = frozenset({"mitre_attack", "mitre_d3fend"})
_ATTACK_FIELDS = frozenset(
    {"repository", "version", "commit", "path", "size", "sha256"}
)
_D3FEND_FIELDS = frozenset({"version", "url", "size", "sha256"})
_FULL_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_VERSION_COMPONENT = re.compile(r"[0-9A-Za-z][0-9A-Za-z._-]*\Z")
_MUTABLE_REFS = frozenset({"current", "head", "latest", "main", "master"})


class ManifestError(ValueError):
    """The validation-data manifest does not satisfy the closed schema."""


class PreparationError(RuntimeError):
    """A pinned validation dataset could not be prepared safely."""


def _manifest_error(message: str) -> ManifestError:
    return ManifestError(f"Invalid Sigma validation-data manifest: {message}")


def _require_object(value: Any, location: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _manifest_error(f"{location} must be a JSON object")
    return value


def _require_exact_fields(
    value: dict[str, Any], expected: frozenset[str], location: str
) -> None:
    actual = set(value)
    if actual == expected:
        return
    details = []
    missing = sorted(expected - actual)
    unknown = sorted(actual - expected)
    if missing:
        details.append(f"missing fields {missing!r}")
    if unknown:
        details.append(f"unknown fields {unknown!r}")
    raise _manifest_error(f"{location} has " + " and ".join(details))


def _require_nonempty_string(value: Any, location: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _manifest_error(f"{location} must be a non-empty trimmed string")
    return value


def _validate_size(value: Any, location: str) -> None:
    if type(value) is not int or value <= 0:
        raise _manifest_error(f"{location} must be a positive integer")


def _validate_sha256(value: Any, location: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise _manifest_error(
            f"{location} must be exactly 64 lowercase hexadecimal characters"
        )


def load_manifest(path: Path) -> dict[str, Any]:
    """Load and strictly validate a Sigma validation-data manifest."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise _manifest_error(f"cannot read {path}: {error}") from error

    manifest = _require_object(document, "root")
    _require_exact_fields(manifest, _TOP_LEVEL_FIELDS, "root")
    if manifest["schema"] != SCHEMA:
        raise _manifest_error(
            f"schema must be {SCHEMA!r}, got {manifest['schema']!r}"
        )

    datasets = _require_object(manifest["datasets"], "datasets")
    _require_exact_fields(datasets, _DATASET_FIELDS, "datasets")

    attack = _require_object(datasets["mitre_attack"], "datasets.mitre_attack")
    _require_exact_fields(attack, _ATTACK_FIELDS, "datasets.mitre_attack")
    repository = _require_nonempty_string(
        attack["repository"], "datasets.mitre_attack.repository"
    )
    if repository != ATTACK_REPOSITORY:
        raise _manifest_error(
            f"datasets.mitre_attack.repository must be {ATTACK_REPOSITORY!r}"
        )
    _require_nonempty_string(attack["version"], "datasets.mitre_attack.version")
    commit = _require_nonempty_string(
        attack["commit"], "datasets.mitre_attack.commit"
    )
    if commit.lower() in _MUTABLE_REFS or _FULL_COMMIT.fullmatch(commit) is None:
        raise _manifest_error(
            "datasets.mitre_attack.commit must be a full 40-character "
            "lowercase hexadecimal commit, not a branch or mutable ref"
        )
    attack_path = _require_nonempty_string(
        attack["path"], "datasets.mitre_attack.path"
    )
    if attack_path != ATTACK_PATH:
        raise _manifest_error(
            f"datasets.mitre_attack.path must be {ATTACK_PATH!r}"
        )
    _validate_size(attack["size"], "datasets.mitre_attack.size")
    _validate_sha256(attack["sha256"], "datasets.mitre_attack.sha256")

    d3fend = _require_object(datasets["mitre_d3fend"], "datasets.mitre_d3fend")
    _require_exact_fields(d3fend, _D3FEND_FIELDS, "datasets.mitre_d3fend")
    d3fend_version = _require_nonempty_string(
        d3fend["version"], "datasets.mitre_d3fend.version"
    )
    if (
        d3fend_version.lower() in _MUTABLE_REFS
        or _VERSION_COMPONENT.fullmatch(d3fend_version) is None
    ):
        raise _manifest_error(
            "datasets.mitre_d3fend.version must be an explicit URL-safe version, "
            "not a mutable ref"
        )
    d3fend_url = _require_nonempty_string(
        d3fend["url"], "datasets.mitre_d3fend.url"
    )
    parsed_url = urlsplit(d3fend_url)
    expected_path = f"/ontologies/d3fend/{d3fend_version}/d3fend.json"
    if (
        parsed_url.scheme != "https"
        or parsed_url.netloc != "d3fend.mitre.org"
        or parsed_url.path != expected_path
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise _manifest_error(
            "datasets.mitre_d3fend.url must be the versioned HTTPS D3FEND "
            f"ontology URL ending in {expected_path!r}"
        )
    _validate_size(d3fend["size"], "datasets.mitre_d3fend.size")
    _validate_sha256(d3fend["sha256"], "datasets.mitre_d3fend.sha256")
    return manifest


def attack_download_url(attack: dict[str, Any]) -> str:
    """Derive the immutable raw ATT&CK URL from validated metadata."""
    return (
        "https://raw.githubusercontent.com/"
        f"{attack['repository']}/{attack['commit']}/{attack['path']}"
    )


def download_dataset(name: str, url: str, destination: Path) -> None:
    """Download one dataset with bounded retries and an atomic final name."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.unlink(missing_ok=True)
    last_error: BaseException | None = None
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                prefix=f".{destination.name}.",
                suffix=".download",
                dir=destination.parent,
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                request = Request(
                    url,
                    headers={"User-Agent": "Alert2IR-Sigma-validation-data/1"},
                )
                with urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                    shutil.copyfileobj(response, temporary)
            temporary_path.replace(destination)
            return
        except (HTTPError, URLError, TimeoutError, OSError) as error:
            last_error = error
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            if attempt < DOWNLOAD_ATTEMPTS:
                time.sleep(attempt)

    raise PreparationError(
        f"Failed to download Sigma validation dataset {name} from {url} "
        f"after {DOWNLOAD_ATTEMPTS} attempts: {last_error}"
    ) from last_error


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_dataset_file(
    name: str, path: Path, expected_size: int, expected_sha256: str
) -> None:
    """Verify exact bytes before allowing a dataset to be parsed."""
    try:
        actual_size = path.stat().st_size
    except OSError as error:
        raise PreparationError(
            f"Sigma validation dataset {name} cannot be read: {error}"
        ) from error
    if actual_size != expected_size:
        raise PreparationError(
            f"Sigma validation dataset {name} size mismatch: "
            f"expected {expected_size}, got {actual_size}"
        )
    try:
        actual_sha256 = _sha256(path)
    except OSError as error:
        raise PreparationError(
            f"Sigma validation dataset {name} cannot be read: {error}"
        ) from error
    if actual_sha256 != expected_sha256:
        raise PreparationError(
            f"Sigma validation dataset {name} SHA-256 mismatch: "
            f"expected {expected_sha256}, got {actual_sha256}"
        )


def _load_dataset_json(name: str, path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PreparationError(
            f"Sigma validation dataset {name} is not valid JSON: {error}"
        ) from error
    if not isinstance(value, dict):
        raise PreparationError(
            f"Sigma validation dataset {name} root must be a JSON object"
        )
    return value


def verify_attack_version(path: Path, expected_version: str) -> None:
    """Verify ATT&CK's x-mitre-collection version marker."""
    document = _load_dataset_json("mitre_attack", path)
    objects = document.get("objects")
    if not isinstance(objects, list):
        raise PreparationError(
            "Sigma validation dataset mitre_attack has no STIX objects array"
        )
    versions = {
        item.get("x_mitre_version")
        for item in objects
        if isinstance(item, dict)
        and item.get("type") == "x-mitre-collection"
        and isinstance(item.get("x_mitre_version"), str)
    }
    if versions != {expected_version}:
        raise PreparationError(
            "Sigma validation dataset mitre_attack embedded version mismatch: "
            f"expected {expected_version}, got {sorted(versions)!r}"
        )


def verify_d3fend_version(path: Path, expected_version: str) -> None:
    """Verify D3FEND's ontology version information and version IRI."""
    document = _load_dataset_json("mitre_d3fend", path)
    graph = document.get("@graph")
    if not isinstance(graph, list):
        raise PreparationError(
            "Sigma validation dataset mitre_d3fend has no JSON-LD @graph array"
        )
    ontologies = [
        item
        for item in graph
        if isinstance(item, dict) and item.get("@type") == "owl:Ontology"
    ]
    versions = {
        item.get("owl:versionInfo")
        for item in ontologies
        if isinstance(item.get("owl:versionInfo"), str)
    }
    version_iris = {
        value["@id"]
        for item in ontologies
        if isinstance((value := item.get("owl:versionIRI")), dict)
        and isinstance(value.get("@id"), str)
    }
    expected_iri_suffix = f"/{expected_version}/d3fend.owl"
    if versions != {expected_version} or not version_iris or not all(
        iri.endswith(expected_iri_suffix) for iri in version_iris
    ):
        raise PreparationError(
            "Sigma validation dataset mitre_d3fend embedded version mismatch: "
            f"expected {expected_version}, got versionInfo={sorted(versions)!r}, "
            f"versionIRI={sorted(version_iris)!r}"
        )


def seed_pysigma_cache(
    cache_home: Path,
    attack_path: Path,
    d3fend_path: Path,
    attack_version: str,
    d3fend_version: str,
) -> Path:
    """Seed both pySigma caches through the loaders' supported public APIs."""
    try:
        from sigma.data import mitre_attack, mitre_d3fend
    except ImportError as error:
        raise PreparationError(
            f"Failed to import the pinned pySigma dataset loaders: {error}"
        ) from error

    cache_root = cache_home / ".cache" / "pysigma"
    try:
        mitre_attack.set_cache_dir(str(cache_root / "mitre_attack"))
        mitre_attack.set_url(str(attack_path))
        loaded_attack_version = mitre_attack.mitre_attack_version
    except Exception as error:
        raise PreparationError(
            f"Failed to seed pySigma cache for mitre_attack: {error}"
        ) from error
    if loaded_attack_version != attack_version:
        raise PreparationError(
            "Seeded pySigma mitre_attack version mismatch: "
            f"expected {attack_version}, got {loaded_attack_version}"
        )

    try:
        mitre_d3fend.set_cache_dir(str(cache_root / "mitre_d3fend"))
        mitre_d3fend.set_url(str(d3fend_path))
        loaded_d3fend_version = mitre_d3fend.mitre_d3fend_version
    except Exception as error:
        raise PreparationError(
            f"Failed to seed pySigma cache for mitre_d3fend: {error}"
        ) from error
    if loaded_d3fend_version != d3fend_version:
        raise PreparationError(
            "Seeded pySigma mitre_d3fend version mismatch: "
            f"expected {d3fend_version}, got {loaded_d3fend_version}"
        )
    return cache_root


def _outside_repository(path: Path, argument: str) -> Path:
    resolved = path.resolve()
    if resolved == REPOSITORY_ROOT or REPOSITORY_ROOT in resolved.parents:
        raise PreparationError(
            f"{argument} must be outside the Git-controlled repository: {resolved}"
        )
    return resolved


def prepare(metadata: Path, download_directory: Path, cache_home: Path) -> None:
    manifest = load_manifest(metadata)
    download_directory = _outside_repository(
        download_directory, "--download-directory"
    )
    cache_home = _outside_repository(cache_home, "--cache-home")
    try:
        download_directory.mkdir(parents=True, exist_ok=True)
        cache_home.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise PreparationError(
            f"Failed to create Sigma validation-data directories: {error}"
        ) from error

    attack = manifest["datasets"]["mitre_attack"]
    d3fend = manifest["datasets"]["mitre_d3fend"]
    attack_path = download_directory / ATTACK_FILENAME
    d3fend_path = download_directory / D3FEND_FILENAME
    attack_url = attack_download_url(attack)

    download_dataset("mitre_attack", attack_url, attack_path)
    verify_dataset_file(
        "mitre_attack", attack_path, attack["size"], attack["sha256"]
    )
    verify_attack_version(attack_path, attack["version"])

    download_dataset("mitre_d3fend", d3fend["url"], d3fend_path)
    verify_dataset_file(
        "mitre_d3fend", d3fend_path, d3fend["size"], d3fend["sha256"]
    )
    verify_d3fend_version(d3fend_path, d3fend["version"])

    cache_root = seed_pysigma_cache(
        cache_home,
        attack_path,
        d3fend_path,
        attack["version"],
        d3fend["version"],
    )
    print("Sigma validation data prepared")
    print(f"ATT&CK version: {attack['version']}")
    print(f"ATT&CK repository: {attack['repository']}")
    print(f"ATT&CK commit: {attack['commit']}")
    print(f"ATT&CK SHA-256: {attack['sha256']}")
    print(f"D3FEND version: {d3fend['version']}")
    print(f"D3FEND URL: {d3fend['url']}")
    print(f"D3FEND SHA-256: {d3fend['sha256']}")
    print(f"pySigma cache root: {cache_root}")


def parse_arguments(arguments: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--download-directory", required=True, type=Path)
    parser.add_argument("--cache-home", required=True, type=Path)
    return parser.parse_args(arguments)


def main(arguments: list[str] | None = None) -> int:
    options = parse_arguments(arguments)
    try:
        prepare(options.metadata, options.download_directory, options.cache_home)
    except (ManifestError, PreparationError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
