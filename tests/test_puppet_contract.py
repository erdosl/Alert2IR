"""Repository contract tests for the WS02 Puppet environment.

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


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PUPPET_ROOT = REPOSITORY_ROOT / "infra" / "puppet"
ARTIFACT_BUILDER = REPOSITORY_ROOT / "tools" / "puppet" / "build-ws02-puppet-artifact.sh"
CANONICAL_SYSMON_XML = REPOSITORY_ROOT / "config" / "sysmon" / "alert2ir-sysmon.xml"

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
        rf"^\s*class\s+{re.escape(class_name)}\s*\{{", source, re.MULTILINE
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

    def test_site_classifies_only_the_two_windows_endpoints_through_the_role(self) -> None:
        source = read_puppet(PUPPET_ROOT / "manifests" / "site.pp")
        classifications: dict[str, set[str]] = {}

        for declaration in NODE_DECLARATION.finditer(source):
            body = braced_body(source, source.index("{", declaration.start(), declaration.end()))
            classes = {
                statement.group("class")
                for statement in CLASSIFICATION_STATEMENT.finditer(body)
            }
            for node_name in re.findall(r"'([^']+)'", declaration.group("names")):
                classifications[node_name] = classes

        self.assertEqual(
            classifications,
            {
                "win11-01": {"role::windows_endpoint"},
                "win11-02": {"role::windows_endpoint"},
            },
        )

    def test_git_tracked_hiera_data_remains_empty(self) -> None:
        tracked = subprocess.run(
            ["git", "ls-files", "--", "infra/puppet/data"],
            cwd=REPOSITORY_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
        data_files = [
            REPOSITORY_ROOT / relative_path
            for relative_path in tracked.stdout.splitlines()
            if Path(relative_path).suffix in {".yaml", ".yml"}
        ]

        self.assertTrue(data_files, "expected Git-tracked Hiera YAML files")
        for data_file in data_files:
            with self.subTest(data_file=data_file.relative_to(REPOSITORY_ROOT)):
                self.assertEqual(data_file.read_text(encoding="utf-8").strip(), "--- {}")

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

            with zipfile.ZipFile(first_artifact) as archive:
                file_names = {
                    entry.filename
                    for entry in archive.infolist()
                    if not entry.is_dir()
                }
                expected_files = self.expected_artifact_files(commit)
                self.assertEqual(file_names, expected_files)
                self.assertTrue(
                    {
                        "environment.conf",
                        "hiera.yaml",
                        "manifests/site.pp",
                        "modules/role/manifests/windows_endpoint.pp",
                        "modules/profile/manifests/sysmon.pp",
                        "modules/profile/manifests/splunk_forwarder.pp",
                    }.issubset(file_names)
                )

                staged_xml = archive.read(
                    "modules/profile/files/sysmon/alert2ir-sysmon.xml"
                )
                self.assertEqual(staged_xml, canonical_bytes)
                self.assertEqual(hashlib.sha256(staged_xml).hexdigest(), canonical_sha256)

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
        } | {"modules/profile/files/sysmon/alert2ir-sysmon.xml"}


if __name__ == "__main__":
    unittest.main()
