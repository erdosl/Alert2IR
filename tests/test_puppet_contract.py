"""Repository contract tests for the Alert2IR Puppet environment.

These tests freeze the reviewed repository boundary; they are not a Puppet
parser, catalog compiler, provider test, or a substitute for endpoint
convergence validation with Puppet 8.20.
"""

import hashlib
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile
import unittest
import zipfile

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PUPPET_ROOT = REPOSITORY_ROOT / "infra" / "puppet"
ARTIFACT_BUILDER = REPOSITORY_ROOT / "tools" / "puppet" / "build-puppet-artifact.sh"
CANONICAL_SYSMON_XML = REPOSITORY_ROOT / "config" / "sysmon" / "alert2ir-sysmon.xml"
CANONICAL_IR_CORE_ALLOY = REPOSITORY_ROOT / "observability" / "alloy" / "ir-core.alloy"
CANONICAL_OBS01_ALLOY = REPOSITORY_ROOT / "observability" / "alloy" / "obs01.alloy"
EXPECTED_PUPPET_ENVIRONMENT_FILES = {
    "README.md",
    "data/common.yaml",
    "data/nodes/dev01.yaml",
    "data/nodes/ir-core.yaml",
    "data/nodes/obs01.yaml",
    "data/nodes/splunk.yaml",
    "data/nodes/win11-01.yaml",
    "data/nodes/win11-02.yaml",
    "environment.conf",
    "hiera.yaml",
    "manifests/site.pp",
    "modules/profile/files/alloy/alert2ir-alloy-containerd-access.sh",
    "modules/profile/files/alloy/apt-preferences",
    "modules/profile/files/alloy/grafana.asc",
    "modules/profile/files/alloy/grafana.list",
    "modules/profile/files/alloy/systemd/20-alert2ir-alloy-containerd-access.conf",
    "modules/profile/files/alloy/systemd/ir-core.conf",
    "modules/profile/files/alloy/systemd/obs01.conf",
    "modules/profile/files/docker/apt-preferences",
    "modules/profile/files/docker/containerd-config.toml",
    "modules/profile/files/docker/docker.asc",
    "modules/profile/files/docker/docker.sources",
    "modules/profile/files/docker/obs01-daemon.json",
    "modules/profile/manifests/alert2ir_host.pp",
    "modules/profile/manifests/alloy.pp",
    "modules/profile/manifests/base.pp",
    "modules/profile/manifests/development.pp",
    "modules/profile/manifests/docker_host.pp",
    "modules/profile/manifests/host_identity_guard.pp",
    "modules/profile/manifests/linux_base.pp",
    "modules/profile/manifests/observability_host.pp",
    "modules/profile/manifests/operator_tools.pp",
    "modules/profile/manifests/splunk_forwarder.pp",
    "modules/profile/manifests/sysmon.pp",
    "modules/role/manifests/development.pp",
    "modules/role/manifests/ir_core.pp",
    "modules/role/manifests/observability.pp",
    "modules/role/manifests/splunk_server.pp",
    "modules/role/manifests/windows_endpoint.pp",
}
STAGED_SYSMON_PATH = "modules/profile/files/sysmon/alert2ir-sysmon.xml"
STAGED_IR_CORE_ALLOY_PATH = "modules/profile/files/alloy/ir-core.alloy"
STAGED_OBS01_ALLOY_PATH = "modules/profile/files/alloy/obs01.alloy"
STAGED_EXTERNAL_PATHS = {
    STAGED_SYSMON_PATH,
    STAGED_IR_CORE_ALLOY_PATH,
    STAGED_OBS01_ALLOY_PATH,
}
EXPECTED_ARTIFACT_FILES = EXPECTED_PUPPET_ENVIRONMENT_FILES | STAGED_EXTERNAL_PATHS

RESOURCE_DECLARATION = re.compile(
    r"""
    ^\s*(?P<resource_type>[a-z][a-z0-9_:]*)\s*\{\s*
    (?P<quote>['\"])(?P<title>[^'\"]+)(?P=quote)\s*:
    """,
    re.MULTILINE | re.VERBOSE,
)
RESOURCE_BLOCK_OPENING = re.compile(
    r"^\s*(?P<resource_type>[a-z][a-z0-9_:]*)\s*\{", re.MULTILINE
)
NODE_DECLARATION = re.compile(
    r"^\s*node\s+(?P<names>(?:'[^']+'\s*,\s*)*'[^']+')\s*\{",
    re.MULTILINE,
)
DEFAULT_NODE_DECLARATION = re.compile(r"^\s*node\s+default\s*\{", re.MULTILINE)
CLASSIFICATION_STATEMENT = re.compile(
    r"^\s*(?:include|contain)\s+(?P<class>[a-z][a-z0-9_:]*)\s*;?\s*$",
    re.MULTILINE,
)


def read_puppet(path: Path) -> str:
    """Return the simple manifest text used by these narrow contract checks."""
    return "\n".join(line.split("#", 1)[0] for line in path.read_text(encoding="utf-8").splitlines())


def braced_body(source: str, opening_brace: int) -> str:
    """Extract one local, balanced manifest block without parsing Puppet syntax."""
    depth = 0
    for index in range(opening_brace, len(source)):
        character = source[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[opening_brace + 1 : index]
    raise AssertionError("unterminated Puppet block in repository contract")


def class_body(source: str, class_name: str) -> str:
    declaration = re.search(
        rf"^\s*class\s+{re.escape(class_name)}(?:\s*\([^)]*\))?\s*\{{",
        source,
        re.MULTILINE,
    )
    if declaration is None:
        raise AssertionError(f"class {class_name} is not declared")
    return braced_body(source, source.index("{", declaration.start(), declaration.end()))


def resource_blocks(source: str) -> list[tuple[str, str, str]]:
    """Return the explicitly titled resource blocks used by the current manifests."""
    resources = []
    for declaration in RESOURCE_DECLARATION.finditer(source):
        opening_brace = source.index("{", declaration.start(), declaration.end())
        resources.append(
            (
                declaration.group("resource_type"),
                declaration.group("title"),
                braced_body(source, opening_brace),
            )
        )
    return resources


def resource_types(source: str) -> list[str]:
    """Return local resource-block types, including future non-literal titles."""
    return [match.group("resource_type") for match in RESOURCE_BLOCK_OPENING.finditer(source)]


def resource_body(source: str, resource_type: str, title: str) -> str:
    matches = [
        body
        for declared_type, declared_title, body in resource_blocks(source)
        if (declared_type, declared_title) == (resource_type, title)
    ]
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one {resource_type}[{title!r}] resource, found {len(matches)}"
        )
    return matches[0]


def assert_property(
    test: unittest.TestCase, resource: str, name: str, value: str
) -> None:
    test.assertRegex(
        resource,
        re.compile(
            rf"^\s*{re.escape(name)}\s*=>\s*{re.escape(value)}\s*,?\s*$",
            re.MULTILINE,
        ),
        f"expected {name} => {value}",
    )


class PuppetRepositoryContractTests(unittest.TestCase):
    def test_windows_endpoint_role_composes_only_the_frozen_profiles(self) -> None:
        source = read_puppet(
            PUPPET_ROOT / "modules" / "role" / "manifests" / "windows_endpoint.pp"
        )
        role = class_body(source, "role::windows_endpoint")

        profiles = [
            match.group("class")
            for match in CLASSIFICATION_STATEMENT.finditer(role)
        ]
        self.assertEqual(
            profiles,
            [
                "profile::base",
                "profile::sysmon",
                "profile::splunk_forwarder",
            ],
        )
        self.assertEqual(resource_types(role), [])

    def test_base_profile_remains_resource_free(self) -> None:
        source = read_puppet(
            PUPPET_ROOT / "modules" / "profile" / "manifests" / "base.pp"
        )
        profile = class_body(source, "profile::base")

        self.assertEqual(resource_types(profile), [])

    def test_linux_roles_compose_only_the_reviewed_pr2_profiles(self) -> None:
        roles = {
            "role::development": (
                "development.pp",
                [
                    "profile::linux_base",
                    "profile::host_identity_guard",
                    "profile::operator_tools",
                    "profile::docker_host",
                    "profile::development",
                ],
            ),
            "role::ir_core": (
                "ir_core.pp",
                [
                    "profile::linux_base",
                    "profile::host_identity_guard",
                    "profile::operator_tools",
                    "profile::docker_host",
                    "profile::alert2ir_host",
                    "profile::alloy",
                ],
            ),
            "role::observability": (
                "observability.pp",
                [
                    "profile::linux_base",
                    "profile::host_identity_guard",
                    "profile::operator_tools",
                    "profile::docker_host",
                    "profile::observability_host",
                    "profile::alloy",
                ],
            ),
            "role::splunk_server": (
                "splunk_server.pp",
                [
                    "profile::linux_base",
                    "profile::host_identity_guard",
                    "profile::operator_tools",
                ],
            ),
        }

        for role_name, (manifest_name, expected_profiles) in roles.items():
            with self.subTest(role=role_name):
                source = read_puppet(
                    PUPPET_ROOT / "modules" / "role" / "manifests" / manifest_name
                )
                role = class_body(source, role_name)
                profiles = [
                    match.group("class")
                    for match in CLASSIFICATION_STATEMENT.finditer(role)
                ]
                self.assertEqual(profiles, expected_profiles)
                self.assertEqual(resource_types(role), [])

                if "profile::alloy" in expected_profiles:
                    self.assertIn(
                        "Class['profile::docker_host'] -> Class['profile::alloy']",
                        role,
                    )
                if role_name == "role::observability":
                    self.assertIn(
                        "Class['profile::observability_host'] -> Class['profile::alloy']",
                        role,
                    )

    def test_linux_base_is_resource_free_and_guards_the_reference_platform(self) -> None:
        source = read_puppet(
            PUPPET_ROOT / "modules" / "profile" / "manifests" / "linux_base.pp"
        )
        profile = class_body(source, "profile::linux_base")

        self.assertEqual(resource_types(profile), [])
        for required_contract in (
            "$facts['kernel']",
            "$facts['os']",
            "'Linux'",
            "'Ubuntu'",
            "'24.04'",
            "'amd64'",
            "'x86_64'",
        ):
            with self.subTest(required_contract=required_contract):
                self.assertIn(required_contract, profile)
        self.assertGreaterEqual(profile.count("fail("), 4)

    def test_operator_tools_owns_only_ripgrep_and_shellcheck(self) -> None:
        source = read_puppet(
            PUPPET_ROOT / "modules" / "profile" / "manifests" / "operator_tools.pp"
        )
        profile = class_body(source, "profile::operator_tools")
        resources = resource_blocks(profile)

        self.assertEqual(resource_types(profile), ["package", "package"])
        self.assertEqual(
            [(resource_type, title) for resource_type, title, _ in resources],
            [("package", "ripgrep"), ("package", "shellcheck")],
        )
        for resource_type, title, body in resources:
            with self.subTest(resource_type=resource_type, title=title):
                assert_property(self, body, "ensure", "installed")

    def test_host_identity_guard_is_read_only_and_interface_independent(self) -> None:
        source = read_puppet(
            PUPPET_ROOT
            / "modules"
            / "profile"
            / "manifests"
            / "host_identity_guard.pp"
        )
        profile = class_body(source, "profile::host_identity_guard")

        self.assertRegex(
            source,
            re.compile(
                r"class\s+profile::host_identity_guard\s*\(\s*"
                r"String\[1\]\s+\$expected_host_only_ipv4\s*,?\s*\)",
                re.MULTILINE,
            ),
        )
        self.assertEqual(resource_types(profile), [])
        for required_contract in (
            "$trusted",
            "['certname']",
            "$facts['networking']",
            "['hostname']",
            "['interfaces']",
            "['bindings']",
            "['address']",
            "$expected_host_only_ipv4",
            ".filter",
            ".length",
        ):
            with self.subTest(required_contract=required_contract):
                self.assertIn(required_contract, profile)
        self.assertIn("$certname != $hostname", profile)
        self.assertGreaterEqual(profile.count("fail("), 6)
        self.assertNotIn("enp0s8", source)
        self.assertNotRegex(profile, r"\bexec\s*\{")

    def test_sysmon_profile_preserves_the_staged_file_and_service_boundary(self) -> None:
        source = read_puppet(
            PUPPET_ROOT / "modules" / "profile" / "manifests" / "sysmon.pp"
        )
        profile = class_body(source, "profile::sysmon")
        resources = resource_blocks(profile)

        self.assertEqual(resource_types(profile), ["file", "file", "file", "service"])

        self.assertEqual(
            [(resource_type, title) for resource_type, title, _ in resources],
            [
                ("file", "C:/ProgramData/Alert2IR"),
                ("file", "C:/ProgramData/Alert2IR/Sysmon"),
                ("file", "C:/ProgramData/Alert2IR/Sysmon/alert2ir-sysmon.xml"),
                ("service", "Sysmon64"),
            ],
        )

        root_directory = resource_body(profile, "file", "C:/ProgramData/Alert2IR")
        sysmon_directory = resource_body(profile, "file", "C:/ProgramData/Alert2IR/Sysmon")
        staged_xml = resource_body(
            profile, "file", "C:/ProgramData/Alert2IR/Sysmon/alert2ir-sysmon.xml"
        )
        service = resource_body(profile, "service", "Sysmon64")

        assert_property(self, root_directory, "ensure", "directory")
        assert_property(self, sysmon_directory, "ensure", "directory")
        assert_property(
            self,
            sysmon_directory,
            "require",
            "File['C:/ProgramData/Alert2IR']",
        )
        assert_property(self, staged_xml, "ensure", "file")
        assert_property(
            self,
            staged_xml,
            "source",
            "'puppet:///modules/profile/sysmon/alert2ir-sysmon.xml'",
        )
        assert_property(
            self,
            staged_xml,
            "require",
            "File['C:/ProgramData/Alert2IR/Sysmon']",
        )
        assert_property(self, service, "ensure", "running")
        assert_property(self, service, "enable", "true")

        self.assertNotIn("package", [resource_type for resource_type, _, _ in resources])
        self.assertNotIn("exec", [resource_type for resource_type, _, _ in resources])
        self.assertNotRegex(
            profile,
            re.compile(r"^\s*(?:notify|subscribe|refreshonly)\s*=>", re.MULTILINE),
            "Sysmon staging must not notify, subscribe, or refresh the service",
        )
        self.assertNotRegex(profile, r"(?:~>|->)")
        self.assertNotIn("Sysmon64.exe", profile)

    def test_splunk_forwarder_profile_owns_only_the_service_state(self) -> None:
        source = read_puppet(
            PUPPET_ROOT
            / "modules"
            / "profile"
            / "manifests"
            / "splunk_forwarder.pp"
        )
        profile = class_body(source, "profile::splunk_forwarder")
        resources = resource_blocks(profile)

        self.assertEqual(resource_types(profile), ["service"])

        self.assertEqual(
            [(resource_type, title) for resource_type, title, _ in resources],
            [("service", "SplunkForwarder")],
        )
        service = resource_body(profile, "service", "SplunkForwarder")
        assert_property(self, service, "ensure", "running")
        assert_property(self, service, "enable", "true")

        self.assertNotIn("inputs.conf", profile.lower())
        self.assertNotIn("outputs.conf", profile.lower())
        self.assertNotRegex(
            profile,
            re.compile(r"^\s*(?:notify|subscribe|refreshonly)\s*=>", re.MULTILINE),
            "Splunk Forwarder service state must not add refresh behavior",
        )
        self.assertNotRegex(profile, r"(?:~>|->)")

    def test_site_explicitly_classifies_the_six_lab_nodes_and_fails_closed_by_default(
        self,
    ) -> None:
        source = read_puppet(PUPPET_ROOT / "manifests" / "site.pp")
        classifications: dict[str, list[str]] = {}

        for declaration in NODE_DECLARATION.finditer(source):
            body = braced_body(
                source,
                source.index("{", declaration.start(), declaration.end()),
            )
            classes = [
                statement.group("class")
                for statement in CLASSIFICATION_STATEMENT.finditer(body)
            ]
            for node_name in re.findall(r"'([^']+)'", declaration.group("names")):
                self.assertNotIn(node_name, classifications)
                classifications[node_name] = classes

        self.assertEqual(
            classifications,
            {
                "win11-01": ["role::windows_endpoint"],
                "win11-02": ["role::windows_endpoint"],
                "splunk": ["role::splunk_server"],
                "ir-core": ["role::ir_core"],
                "dev01": ["role::development"],
                "obs01": ["role::observability"],
            },
        )

        defaults = list(DEFAULT_NODE_DECLARATION.finditer(source))
        self.assertEqual(len(defaults), 1)
        default_body = braced_body(
            source,
            source.index("{", defaults[0].start(), defaults[0].end()),
        )
        self.assertRegex(default_body, r"\bfail\s*\(")
        self.assertEqual(list(CLASSIFICATION_STATEMENT.finditer(default_body)), [])
        self.assertEqual(resource_types(default_body), [])

    def test_hiera_yaml_is_valid_and_mapping_typed(self) -> None:
        data_files = sorted((PUPPET_ROOT / "data").rglob("*.yaml"))
        self.assertTrue(data_files, "expected Hiera YAML files")
        for data_file in data_files:
            with self.subTest(data_file=data_file.relative_to(REPOSITORY_ROOT)):
                data = yaml.safe_load(data_file.read_text(encoding="utf-8"))
                self.assertIsInstance(data, dict)
                self.assertTrue(all(isinstance(key, str) for key in data))

    def test_hiera_contains_only_reviewed_public_pr2_data(self) -> None:
        expected = {
            "common.yaml": {},
            "nodes/dev01.yaml": {
                "profile::host_identity_guard::expected_host_only_ipv4": "192.168.56.64"
            },
            "nodes/ir-core.yaml": {
                "profile::host_identity_guard::expected_host_only_ipv4": "192.168.56.63",
                "profile::alloy::config_source": "ir-core.alloy",
                "profile::alloy::storage_path": "/var/lib/alloy/alert2ir",
                "profile::alloy::systemd_dropin_source": "ir-core.conf",
            },
            "nodes/obs01.yaml": {
                "profile::host_identity_guard::expected_host_only_ipv4": "192.168.56.65",
                "profile::alloy::config_source": "obs01.alloy",
                "profile::alloy::storage_path": "/srv/alert2ir-observability/alloy",
                "profile::alloy::systemd_dropin_source": "obs01.conf",
                "profile::docker_host::daemon_config_source": "obs01-daemon.json",
            },
            "nodes/splunk.yaml": {
                "profile::host_identity_guard::expected_host_only_ipv4": "192.168.56.61"
            },
            "nodes/win11-01.yaml": {},
            "nodes/win11-02.yaml": {},
        }
        actual = {
            data_file.relative_to(PUPPET_ROOT / "data").as_posix(): yaml.safe_load(
                data_file.read_text(encoding="utf-8")
            )
            for data_file in sorted((PUPPET_ROOT / "data").rglob("*.yaml"))
        }

        self.assertEqual(actual, expected)

    def test_hiera_has_no_obvious_secret_markers(self) -> None:
        # Defense in depth only: the exact key/value allowlist above is the authority.
        prohibited_markers = (
            "password",
            "secret",
            "token",
            "private_key",
            "private-key",
            "client_secret",
            "api_key",
            "begin private key",
            "begin openssh private key",
        )
        for data_file in sorted((PUPPET_ROOT / "data").rglob("*.yaml")):
            serialized = data_file.read_text(encoding="utf-8").lower()
            for marker in prohibited_markers:
                with self.subTest(
                    data_file=data_file.relative_to(REPOSITORY_ROOT), marker=marker
                ):
                    self.assertNotIn(marker, serialized)

    def test_puppet_environment_file_set_is_exact(self) -> None:
        actual_files = {
            path.relative_to(PUPPET_ROOT).as_posix()
            for path in PUPPET_ROOT.rglob("*")
            if path.is_file()
        }
        self.assertEqual(actual_files, EXPECTED_PUPPET_ENVIRONMENT_FILES)

    def test_git_derived_puppet_artifact_is_reproducible_and_scoped(self) -> None:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            first_artifact, first_output = self.build_artifact(temporary_root / "first", commit)
            second_artifact, second_output = self.build_artifact(temporary_root / "second", commit)

            self.assertIn(f"Git commit: {commit}", first_output)
            self.assertIn(f"Git commit: {commit}", second_output)
            self.assertEqual(first_artifact.read_bytes(), second_artifact.read_bytes())

            canonical_bytes = CANONICAL_SYSMON_XML.read_bytes()
            canonical_sha256 = hashlib.sha256(canonical_bytes).hexdigest()
            self.assertIn(f"Staged Sysmon XML SHA-256: {canonical_sha256}", first_output)

            canonical_alloy = {
                STAGED_IR_CORE_ALLOY_PATH: CANONICAL_IR_CORE_ALLOY.read_bytes(),
                STAGED_OBS01_ALLOY_PATH: CANONICAL_OBS01_ALLOY.read_bytes(),
            }
            for staged_path, staged_bytes in canonical_alloy.items():
                staged_name = "ir-core" if "ir-core" in staged_path else "obs01"
                staged_sha256 = hashlib.sha256(staged_bytes).hexdigest()
                self.assertIn(
                    f"Staged {staged_name} Alloy SHA-256: {staged_sha256}",
                    first_output,
                )

            with zipfile.ZipFile(first_artifact) as archive:
                file_names = {
                    entry.filename
                    for entry in archive.infolist()
                    if not entry.is_dir()
                }
                expected_files = self.expected_artifact_files(commit)
                self.assertEqual(file_names, expected_files)
                self.assertTrue(file_names.issubset(EXPECTED_ARTIFACT_FILES))

                staged_xml = archive.read(
                    STAGED_SYSMON_PATH
                )
                self.assertEqual(staged_xml, canonical_bytes)
                self.assertEqual(hashlib.sha256(staged_xml).hexdigest(), canonical_sha256)

                for staged_path, canonical_alloy_bytes in canonical_alloy.items():
                    staged_alloy = archive.read(staged_path)
                    self.assertEqual(staged_alloy, canonical_alloy_bytes)
                    self.assertEqual(
                        hashlib.sha256(staged_alloy).hexdigest(),
                        hashlib.sha256(canonical_alloy_bytes).hexdigest(),
                    )

            for artifact_name in file_names:
                parts = {part.lower() for part in PurePosixPath(artifact_name).parts}
                with self.subTest(artifact_name=artifact_name):
                    self.assertFalse({".git", ".venv", ".env"} & parts)
                    self.assertFalse(
                        {"credential", "credentials", "secret", "secrets", "id_rsa"} & parts
                    )

    def build_artifact(self, output_directory: Path, commit: str) -> tuple[Path, str]:
        output_directory.mkdir()
        result = subprocess.run(
            ["bash", str(ARTIFACT_BUILDER), commit, str(output_directory)],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        artifact_path = re.search(r"^Artifact path: (?P<path>.+)$", result.stdout, re.MULTILINE)
        self.assertIsNotNone(artifact_path, result.stdout)
        artifact = Path(artifact_path.group("path"))
        self.assertTrue(artifact.is_file(), result.stdout)
        return artifact, result.stdout

    def expected_artifact_files(self, commit: str) -> set[str]:
        result = subprocess.run(
            ["git", "ls-tree", "-r", "--name-only", commit, "--", "infra/puppet"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        return {
            PurePosixPath(path).relative_to("infra/puppet").as_posix()
            for path in result.stdout.splitlines()
        } | STAGED_EXTERNAL_PATHS


if __name__ == "__main__":
    unittest.main()
