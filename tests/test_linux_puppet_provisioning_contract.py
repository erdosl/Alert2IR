"""Exact repository contracts for PR2 Linux host provisioning.

These checks intentionally validate reviewed repository ownership and public
artifact identities. They are not a Puppet catalog compiler or live-host test.
"""

import hashlib
import json
from pathlib import Path
import re
import tomllib
import unittest

from tests.test_puppet_contract import (
    PUPPET_ROOT,
    assert_property,
    class_body,
    read_puppet,
    resource_blocks,
    resource_body,
    resource_types,
)


PROFILE_ROOT = PUPPET_ROOT / "modules" / "profile"
MANIFEST_ROOT = PROFILE_ROOT / "manifests"
FILE_ROOT = PROFILE_ROOT / "files"
PUPPET_README = PUPPET_ROOT / "README.md"

EXPECTED_PUBLIC_SHA256 = {
    "docker/docker.asc": "1500c1f56fa9e26b9b8f42452a553675796ade0807cdce11975eb98170b3a570",
    "docker/docker.sources": "8f33259a79a8149bed86c66e103fb4c3fa70f9219cd7ff315b6cc30988afef0c",
    "docker/containerd-config.toml": "e2bdf61ad4c980e7439ed09a1ab65441afadede63087761679a97cc77cd4d20d",
    "docker/obs01-daemon.json": "f2ed05c6f5934a15f12571139bdc225804f67b8c83561cc39868f7b2296d2697",
    "alloy/grafana.asc": "d8f5f6f4c174c3b9184cb6ebbf691a2ee69831a109425de4e821f5b43c53a2f8",
    "alloy/grafana.list": "863616f8c5848c32fc1e1024007835dd0cb2447def236d6542f0b1aab9b729f2",
    "alloy/systemd/ir-core.conf": "c3d03d626899e5a85fa7dfb6d49de9e733d2a3c4980634ffeedb75bad5ecc398",
    "alloy/systemd/obs01.conf": "35cfdb13ee3116a3123ff16709a09da2fd8eebde07db6716c88505ac549e920d",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_apt_preferences(path: Path) -> dict[str, tuple[str, int]]:
    parsed: dict[str, tuple[str, int]] = {}
    for paragraph in path.read_text(encoding="utf-8").strip().split("\n\n"):
        fields = dict(line.split(":", 1) for line in paragraph.splitlines())
        package = fields["Package"].strip()
        pin_type, pin_value = fields["Pin"].strip().split(maxsplit=1)
        if pin_type != "version":
            raise AssertionError(f"unexpected pin type for {package}: {pin_type}")
        parsed[package] = (pin_value, int(fields["Pin-Priority"].strip()))
    return parsed


class LinuxPuppetProvisioningContractTests(unittest.TestCase):
    def test_docker_host_owns_only_reviewed_packages_files_and_services(self) -> None:
        source = read_puppet(MANIFEST_ROOT / "docker_host.pp")
        profile = class_body(source, "profile::docker_host")
        packages = [
            (title, body)
            for resource_type, title, body in resource_blocks(profile)
            if resource_type == "package"
        ]
        self.assertEqual(
            [title for title, _ in packages],
            [
                "ca-certificates",
                "containerd.io",
                "docker-ce",
                "docker-ce-cli",
                "docker-buildx-plugin",
                "docker-compose-plugin",
            ],
        )
        assert_property(self, packages[0][1], "ensure", "installed")

        services = [
            title
            for resource_type, title, _ in resource_blocks(profile)
            if resource_type == "service"
        ]
        self.assertEqual(services, ["containerd", "docker"])
        for service_name in services:
            service = resource_body(profile, "service", service_name)
            assert_property(self, service, "ensure", "running")
            assert_property(self, service, "enable", "true")

        self.assertEqual(set(resource_types(profile)), {"exec", "file", "package", "service"})
        self.assertIn("Optional[String[1]] $daemon_config_source = undef", source)
        self.assertIn("ensure  => absent", profile)
        self.assertNotRegex(profile, r"\b(?:user|group|docker::|firewall)\s*\{")
        self.assertNotIn("docker compose", profile.lower())
        self.assertNotIn("apt-mark", profile)
        self.assertNotIn("apt-get upgrade", profile)
        self.assertNotIn("dist-upgrade", profile)
        self.assertNotRegex(profile, r"systemctl\s+restart\s+(?:docker|containerd)")
        self.assertNotRegex(profile, r"(?:purge|recurse)\s*=>\s*true")

    def test_docker_versions_and_preferences_are_exact(self) -> None:
        source = read_puppet(MANIFEST_ROOT / "docker_host.pp")
        profile = class_body(source, "profile::docker_host")
        expected = {
            "containerd.io": "2.3.3-1~ubuntu.24.04~noble",
            "docker-ce": "5:29.7.2-1~ubuntu.24.04~noble",
            "docker-ce-cli": "5:29.7.2-1~ubuntu.24.04~noble",
            "docker-buildx-plugin": "0.36.1-1~ubuntu.24.04~noble",
            "docker-compose-plugin": "5.4.0-1~ubuntu.24.04~noble",
        }
        for package, version in expected.items():
            assert_property(self, resource_body(profile, "package", package), "ensure", f"'{version}'")

        expected_preferences = {package: (version, 1001) for package, version in expected.items()}
        self.assertEqual(
            parse_apt_preferences(FILE_ROOT / "docker" / "apt-preferences"),
            expected_preferences,
        )
        self.assertNotIn("ca-certificates", expected_preferences)

    def test_docker_public_repository_material_is_exact(self) -> None:
        for relative_path in (
            "docker/docker.asc",
            "docker/docker.sources",
            "docker/obs01-daemon.json",
        ):
            with self.subTest(relative_path=relative_path):
                self.assertEqual(sha256(FILE_ROOT / relative_path), EXPECTED_PUBLIC_SHA256[relative_path])

        source = (FILE_ROOT / "docker" / "docker.sources").read_text(encoding="utf-8")
        self.assertEqual(
            source,
            "Types: deb\n"
            "URIs: https://download.docker.com/linux/ubuntu\n"
            "Suites: noble\n"
            "Components: stable\n"
            "Architectures: amd64\n"
            "Signed-By: /etc/apt/keyrings/docker.asc\n",
        )
        daemon = json.loads((FILE_ROOT / "docker" / "obs01-daemon.json").read_text(encoding="utf-8"))
        self.assertEqual(
            daemon,
            {"log-driver": "json-file", "log-opts": {"max-size": "10m", "max-file": "3"}},
        )
        self.assertIn(
            "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
            PUPPET_README.read_text(encoding="utf-8"),
        )

    def test_containerd_baseline_has_no_alert2ir_numeric_socket_gid(self) -> None:
        path = FILE_ROOT / "docker" / "containerd-config.toml"
        self.assertEqual(sha256(path), EXPECTED_PUBLIC_SHA256["docker/containerd-config.toml"])
        with path.open("rb") as stream:
            self.assertEqual(tomllib.load(stream), {"disabled_plugins": ["cri"]})

    def test_alloy_profile_owns_only_reviewed_native_host_state(self) -> None:
        source = read_puppet(MANIFEST_ROOT / "alloy.pp")
        profile = class_body(source, "profile::alloy")
        self.assertEqual(
            set(resource_types(profile)),
            {"exec", "file", "group", "package", "service", "user"},
        )
        self.assertIn("String[1] $config_source", source)
        self.assertIn("String[1] $storage_path", source)
        self.assertIn("String[1] $systemd_dropin_source", source)
        assert_property(self, resource_body(profile, "package", "alloy"), "ensure", "'1.18.1-1'")
        assert_property(self, resource_body(profile, "group", "alloy-containerd"), "system", "true")
        alloy_user = resource_body(profile, "user", "alloy")
        assert_property(self, alloy_user, "membership", "minimum")
        self.assertIn("['docker', 'alloy-containerd']", alloy_user)
        self.assertNotRegex(
            resource_body(profile, "group", "alloy-containerd"),
            re.compile(r"^\s*gid\s*=>", re.MULTILINE),
        )
        alloy_service = resource_body(profile, "service", "alloy")
        assert_property(self, alloy_service, "ensure", "running")
        assert_property(self, alloy_service, "enable", "true")
        self.assertNotRegex(profile, r"systemctl\s+restart\s+(?:docker|containerd)")
        self.assertNotIn("docker compose", profile.lower())
        self.assertNotRegex(profile, r"\b(?:firewall|ufw|iptables|nft)\b")
        self.assertIn("$expected_storage_path = '/srv/alert2ir-observability/alloy'", profile)
        self.assertRegex(
            profile,
            re.compile(
                r"file\s*\{\s*\$storage_path:\s*"
                r"ensure\s*=>\s*directory,\s*"
                r"owner\s*=>\s*'alloy',\s*"
                r"group\s*=>\s*'alloy',\s*"
                r"mode\s*=>\s*'0750',",
                re.MULTILINE,
            ),
        )

    def test_alloy_package_and_repository_material_are_exact(self) -> None:
        self.assertEqual(
            parse_apt_preferences(FILE_ROOT / "alloy" / "apt-preferences"),
            {"alloy": ("1.18.1-1", 1001)},
        )
        for relative_path in (
            "alloy/grafana.asc",
            "alloy/grafana.list",
            "alloy/systemd/ir-core.conf",
            "alloy/systemd/obs01.conf",
        ):
            with self.subTest(relative_path=relative_path):
                self.assertEqual(sha256(FILE_ROOT / relative_path), EXPECTED_PUBLIC_SHA256[relative_path])
        self.assertEqual(
            (FILE_ROOT / "alloy" / "grafana.list").read_text(encoding="utf-8"),
            "deb [signed-by=/etc/apt/keyrings/grafana.asc] https://apt.grafana.com stable main\n",
        )
        self.assertIn(
            "B53AE77BADB630A683046005963FA27710458545",
            PUPPET_README.read_text(encoding="utf-8"),
        )

    def test_alloy_git_configs_have_the_reviewed_canonical_hashes(self) -> None:
        canonical = {
            "ir-core.alloy": "aab02c7f7df8598940e82f4a256f85cacde966749d98968238c6aeafc68496f5",
            "obs01.alloy": "b7acd9599d76eb049901fbf6c2dfd5e7546814c398f80670726806074ddb0bde",
        }
        repository_alloy = PUPPET_ROOT.parents[1] / "observability" / "alloy"
        for filename, expected_hash in canonical.items():
            with self.subTest(filename=filename):
                self.assertEqual(sha256(repository_alloy / filename), expected_hash)
                self.assertFalse((FILE_ROOT / "alloy" / filename).exists())

    def test_alloy_uses_canonical_staged_configs_and_controlled_events(self) -> None:
        source = read_puppet(MANIFEST_ROOT / "alloy.pp")
        profile = class_body(source, "profile::alloy")
        config = resource_body(profile, "file", "/etc/alloy/config.alloy")
        self.assertIn("puppet:///modules/profile/alloy/${config_source}", config)
        assert_property(self, config, "validate_cmd", "'/usr/bin/alloy validate %'")
        reload_exec = resource_body(profile, "exec", "alert2ir-alloy-config-reload")
        assert_property(self, reload_exec, "command", "'/usr/bin/systemctl reload alloy.service'")
        assert_property(self, reload_exec, "refreshonly", "true")
        restart_exec = resource_body(profile, "exec", "alert2ir-alloy-restart")
        assert_property(self, restart_exec, "command", "'/usr/bin/systemctl restart alloy.service'")
        assert_property(self, restart_exec, "refreshonly", "true")
        self.assertNotRegex(config, r"Service\['alloy'\]")

    def test_alloy_containerd_access_is_name_based_and_numeric_gid_free(self) -> None:
        helper = (FILE_ROOT / "alloy" / "alert2ir-alloy-containerd-access.sh").read_text(encoding="utf-8")
        dropin = (
            FILE_ROOT / "alloy" / "systemd" / "20-alert2ir-alloy-containerd-access.conf"
        ).read_text(encoding="utf-8")
        self.assertIn("readonly SOCKET_PATH=/run/containerd/containerd.sock", helper)
        self.assertIn("readonly ACCESS_GROUP=alloy-containerd", helper)
        self.assertIn("[[ ! -S $SOCKET_PATH ]]", helper)
        self.assertIn("/usr/bin/chgrp -- \"$ACCESS_GROUP\" \"$SOCKET_PATH\"", helper)
        self.assertIn("/usr/bin/chmod -- 0660 \"$SOCKET_PATH\"", helper)
        self.assertNotIn("ttrpc", helper)
        self.assertNotRegex(helper, r"\b(?:chown|rm|touch|systemctl)\b")
        self.assertNotRegex(helper + dropin, r"\b(?:984|986)\b")
        check_arm = helper.split("  check)\n", 1)[1].split("    ;;", 1)[0]
        self.assertEqual(check_arm.strip(), "check_access")
        self.assertEqual(
            dropin,
            "[Service]\n"
            "ExecStartPost=/usr/local/sbin/alert2ir-alloy-containerd-access apply\n",
        )
        profile = read_puppet(MANIFEST_ROOT / "alloy.pp")
        access_exec = resource_body(class_body(profile, "profile::alloy"), "exec", "alert2ir-alloy-containerd-access")
        assert_property(
            self,
            access_exec,
            "unless",
            "'/usr/local/sbin/alert2ir-alloy-containerd-access check'",
        )

    def test_development_profile_owns_only_git(self) -> None:
        source = read_puppet(MANIFEST_ROOT / "development.pp")
        profile = class_body(source, "profile::development")
        self.assertEqual(resource_types(profile), ["package"])
        self.assertEqual(
            [(resource_type, title) for resource_type, title, _ in resource_blocks(profile)],
            [("package", "git")],
        )
        assert_property(self, resource_body(profile, "package", "git"), "ensure", "installed")

    def test_alert2ir_host_owns_only_stable_parent_directories(self) -> None:
        source = read_puppet(MANIFEST_ROOT / "alert2ir_host.pp")
        profile = class_body(source, "profile::alert2ir_host")
        resources = resource_blocks(profile)
        self.assertEqual(
            [title for resource_type, title, _ in resources if resource_type == "file"],
            ["/opt/alert2ir", "/opt/alert2ir/releases", "/etc/alert2ir", "/etc/alert2ir/secrets"],
        )
        self.assertNotIn("current", profile)
        self.assertNotIn("runtime.env", profile)

    def test_observability_host_owns_only_stable_host_roots(self) -> None:
        source = read_puppet(MANIFEST_ROOT / "observability_host.pp")
        profile = class_body(source, "profile::observability_host")
        expected = {
            "/opt/alert2ir-observability": ("'root'", "'root'", "'0755'"),
            "/opt/alert2ir-observability/releases": ("'root'", "'root'", "'0755'"),
            "/etc/alert2ir-observability": ("'root'", "'root'", "'0755'"),
            "/etc/alert2ir-observability/secrets": ("'root'", "'root'", "'0750'"),
            "/srv/alert2ir-observability": ("'root'", "'root'", "'0755'"),
        }
        self.assertEqual(
            [title for resource_type, title, _ in resource_blocks(profile) if resource_type == "file"],
            list(expected),
        )
        for path, (owner, group, mode) in expected.items():
            body = resource_body(profile, "file", path)
            assert_property(self, body, "owner", owner)
            assert_property(self, body, "group", group)
            assert_property(self, body, "mode", mode)
        deployment_owned = {
            "alertmanager",
            "prometheus",
            "grafana",
            "loki",
            "tempo",
        }
        for service in deployment_owned:
            self.assertNotIn(f"/srv/alert2ir-observability/{service}", profile)
        self.assertNotRegex(profile, r"\b(?:472|10001|65534)\b")
        self.assertNotRegex(profile, r"(?:purge|recurse)\s*=>\s*true")
        self.assertNotIn("/srv/alert2ir-observability/alloy", profile)
        self.assertNotIn("current", profile)
        self.assertNotIn("runtime.env", profile)

    def test_pr2_does_not_cross_deferred_authority_boundaries(self) -> None:
        pr2_profiles = "\n".join(
            (MANIFEST_ROOT / name).read_text(encoding="utf-8")
            for name in (
                "docker_host.pp",
                "alloy.pp",
                "development.pp",
                "alert2ir_host.pp",
                "observability_host.pp",
            )
        ).lower()
        prohibited = (
            r"package\s*\{\s*['\"]splunk['\"]",
            r"package\s*\{\s*['\"]velociraptor",
            r"server\.config\.yaml",
            r"package\s*\{\s*['\"]bind9",
            r"service\s*\{\s*['\"]named",
            r"service\s*\{\s*['\"]ssh",
            r"authorized_keys",
            r"\bsudoers\b",
            r"\bufw\b",
            r"\biptables\b",
            r"\bnft(?:ables)?\b",
            r"docker-user",
            r"docker\s+compose",
            r"compose\.yaml",
            r"(?:8001|4317)",
        )
        for pattern in prohibited:
            with self.subTest(pattern=pattern):
                self.assertNotRegex(pr2_profiles, pattern)


if __name__ == "__main__":
    unittest.main()
