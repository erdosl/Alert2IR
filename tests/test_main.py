import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


DATABASE_URL = "postgresql://unused:unused@database.invalid:5432/unused"
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRECTORY = REPOSITORY_ROOT / "src"
BACKEND_SETTING = "ALERT2IR_BACKEND"
VELOCIRAPTOR_SETTINGS = (
    "ALERT2IR_VELOCIRAPTOR_API_CONFIG_PATH",
    "ALERT2IR_VELOCIRAPTOR_HOST",
    "ALERT2IR_VELOCIRAPTOR_CLIENT_ID",
)
RUNTIME_SETTINGS = (BACKEND_SETTING, *VELOCIRAPTOR_SETTINGS)

MOCK_INSPECTION_SCRIPT = """
import json
from unittest.mock import patch

import alert2ir.backends as backend_exports

with patch.object(
    backend_exports, "PyVelociraptorCollectionClient"
) as client_constructor, patch.object(
    backend_exports, "VelociraptorBackend"
) as backend_constructor:
    import alert2ir.main as runtime

    backends = runtime.orchestrator.router.backends
    client_constructor.assert_not_called()
    backend_constructor.assert_not_called()
    print(json.dumps({
        "backend_count": len(backends),
        "backend_type": type(backends[0]).__name__,
        "backend_name": backends[0].name,
        "capabilities": sorted(backends[0].capabilities),
        "velociraptor_settings": list(
            runtime._VELOCIRAPTOR_APPLICATION_SETTINGS
        ),
    }))
"""

LIVE_INSPECTION_SCRIPT = """
import json
import os
from unittest.mock import patch

import alert2ir.backends.velociraptor as velociraptor_module

synthetic_configuration = {
    "api_connection_string": "api.invalid:8001",
    "ca_certificate": "synthetic-ca",
    "client_private_key": "synthetic-key",
    "client_cert": "synthetic-certificate",
}

with patch.object(
    velociraptor_module.pyvelociraptor,
    "LoadConfigFile",
    return_value=synthetic_configuration,
) as load_config, patch.object(
    velociraptor_module.grpc, "secure_channel"
) as secure_channel, patch.object(
    velociraptor_module.api_pb2_grpc, "APIStub"
) as api_stub, patch.object(
    velociraptor_module.PyVelociraptorCollectionClient,
    "collect",
    autospec=True,
) as collect:
    import alert2ir.main as runtime

    backends = runtime.orchestrator.router.backends
    backend = backends[0]
    client = backend.client
    load_config.assert_called_once_with(
        os.environ["ALERT2IR_VELOCIRAPTOR_API_CONFIG_PATH"]
    )
    secure_channel.assert_not_called()
    api_stub.assert_not_called()
    collect.assert_not_called()
    print(json.dumps({
        "backend_count": len(backends),
        "backend_type": type(backend).__name__,
        "client_type": type(client).__name__,
        "client_path": str(client._api_config_path),
        "host_client_ids": dict(backend.host_client_ids),
        "timeout": backend.collection_timeout_seconds,
        "contains_mock": any(
            type(configured_backend).__name__ == "MockBackend"
            for configured_backend in backends
        ),
    }))
"""


def runtime_environment(
    configured_values: dict[str, str] | None = None,
) -> dict[str, str]:
    environment = os.environ.copy()
    for name in RUNTIME_SETTINGS:
        environment.pop(name, None)
    existing_python_path = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(SOURCE_DIRECTORY)
    if existing_python_path:
        environment["PYTHONPATH"] += os.pathsep + existing_python_path
    environment["ALERT2IR_DATABASE_URL"] = DATABASE_URL
    if configured_values is not None:
        environment.update(configured_values)
    return environment


def complete_live_environment(api_config_path: str) -> dict[str, str]:
    return runtime_environment(
        {
            BACKEND_SETTING: "velociraptor",
            VELOCIRAPTOR_SETTINGS[0]: api_config_path,
            VELOCIRAPTOR_SETTINGS[1]: "synthetic-host",
            VELOCIRAPTOR_SETTINGS[2]: "C.SYNTHETIC",
        }
    )


class RuntimeCompositionTests(unittest.TestCase):
    def parse_composition_output(self, stdout: str) -> dict[str, object]:
        documents = [json.loads(line) for line in stdout.splitlines() if line]
        self.assertGreaterEqual(len(documents), 2)
        startup = documents[-2]
        self.assertEqual(startup["event"], "service.started")
        self.assertEqual(startup["persistence"], "postgresql")
        for prohibited in ("database_url", "api_config_path", "token", "password"):
            self.assertNotIn(prohibited, startup)
        return documents[-1]

    def run_python(
        self,
        script: str,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-c", script],
            env=environment,
            capture_output=True,
            text=True,
        )

    def assert_import_fails(
        self,
        environment: dict[str, str],
        expected_message: str,
    ) -> None:
        result = self.run_python("import alert2ir.main", environment)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn(expected_message, result.stderr)

    def inspect_mock_composition(
        self,
        configured_backend: str | None,
    ) -> dict[str, object]:
        configured_values = (
            None
            if configured_backend is None
            else {BACKEND_SETTING: configured_backend}
        )
        result = self.run_python(
            MOCK_INSPECTION_SCRIPT,
            runtime_environment(configured_values),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return self.parse_composition_output(result.stdout)

    def test_absent_backend_selector_constructs_singleton_mock(self) -> None:
        composition = self.inspect_mock_composition(None)

        self.assertEqual(composition["backend_count"], 1)
        self.assertEqual(composition["backend_type"], "MockBackend")
        self.assertEqual(composition["backend_name"], "mock")
        self.assertEqual(composition["capabilities"], ["process.list"])

    def test_explicit_mock_constructs_singleton_mock(self) -> None:
        composition = self.inspect_mock_composition("mock")

        self.assertEqual(composition["backend_count"], 1)
        self.assertEqual(composition["backend_type"], "MockBackend")
        self.assertEqual(composition["backend_name"], "mock")
        self.assertEqual(composition["capabilities"], ["process.list"])

    def test_application_expects_only_path_host_and_client_live_settings(self) -> None:
        composition = self.inspect_mock_composition(None)

        self.assertEqual(
            composition["velociraptor_settings"],
            list(VELOCIRAPTOR_SETTINGS),
        )
        setting_names = " ".join(composition["velociraptor_settings"])
        for prohibited_name in (
            "API_CONFIG_SOURCE",
            "PRIVATE_KEY",
            "CA_CERTIFICATE",
            "CLIENT_CERT",
        ):
            self.assertNotIn(prohibited_name, setting_names)

    def test_live_composition_is_singleton_exact_and_does_not_connect(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            api_config_path = Path(temporary_directory) / "synthetic-api.yaml"
            api_config_path.write_text("# synthetic non-secret test file\n")
            environment = complete_live_environment(str(api_config_path))

            result = self.run_python(LIVE_INSPECTION_SCRIPT, environment)

        self.assertEqual(result.returncode, 0, result.stderr)
        composition = self.parse_composition_output(result.stdout)
        self.assertEqual(composition["backend_count"], 1)
        self.assertEqual(composition["backend_type"], "VelociraptorBackend")
        self.assertEqual(
            composition["client_type"], "PyVelociraptorCollectionClient"
        )
        self.assertEqual(composition["client_path"], str(api_config_path))
        self.assertEqual(
            composition["host_client_ids"],
            {"synthetic-host": "C.SYNTHETIC"},
        )
        self.assertEqual(composition["timeout"], 60.0)
        self.assertFalse(composition["contains_mock"])

    def test_unknown_blank_and_padded_backend_selectors_fail(self) -> None:
        for selector in ("", "other", " mock", "mock ", "Velociraptor"):
            with self.subTest(selector=selector):
                self.assert_import_fails(
                    runtime_environment({BACKEND_SETTING: selector}),
                    "ALERT2IR_BACKEND must be exactly 'mock' or 'velociraptor'",
                )

    def test_each_missing_live_setting_fails(self) -> None:
        environment = complete_live_environment("synthetic-api.yaml")
        for setting in VELOCIRAPTOR_SETTINGS:
            with self.subTest(setting=setting):
                incomplete_environment = environment.copy()
                incomplete_environment.pop(setting)
                self.assert_import_fails(
                    incomplete_environment,
                    f"{setting} must be set to a non-empty value",
                )

    def test_each_blank_live_setting_fails(self) -> None:
        environment = complete_live_environment("synthetic-api.yaml")
        for setting in VELOCIRAPTOR_SETTINGS:
            with self.subTest(setting=setting):
                invalid_environment = environment.copy()
                invalid_environment[setting] = ""
                self.assert_import_fails(
                    invalid_environment,
                    f"{setting} must be set to a non-empty value",
                )

    def test_each_padded_live_setting_fails_without_stripping(self) -> None:
        environment = complete_live_environment("synthetic-api.yaml")
        for setting in VELOCIRAPTOR_SETTINGS:
            for configured_value in (
                f" {environment[setting]}",
                f"{environment[setting]} ",
            ):
                with self.subTest(setting=setting, configured_value=configured_value):
                    invalid_environment = environment.copy()
                    invalid_environment[setting] = configured_value
                    self.assert_import_fails(
                        invalid_environment,
                        f"{setting} must be set to a non-empty value",
                    )

    def test_partial_host_client_configuration_fails(self) -> None:
        complete_environment = complete_live_environment("synthetic-api.yaml")
        for missing_setting in VELOCIRAPTOR_SETTINGS[1:]:
            with self.subTest(missing_setting=missing_setting):
                incomplete_environment = complete_environment.copy()
                incomplete_environment.pop(missing_setting)
                self.assert_import_fails(
                    incomplete_environment,
                    f"{missing_setting} must be set to a non-empty value",
                )

    def test_any_live_setting_in_mock_or_default_mode_fails(self) -> None:
        for backend in (None, "mock"):
            for setting in VELOCIRAPTOR_SETTINGS:
                with self.subTest(backend=backend, setting=setting):
                    configured_values = {setting: ""}
                    if backend is not None:
                        configured_values[BACKEND_SETTING] = backend
                    self.assert_import_fails(
                        runtime_environment(configured_values),
                        "Velociraptor application settings require "
                        "ALERT2IR_BACKEND='velociraptor'",
                    )

    def test_missing_local_api_config_file_fails_during_composition(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing_path = Path(temporary_directory) / "missing-api.yaml"
            self.assert_import_fails(
                complete_live_environment(str(missing_path)),
                "Velociraptor API configuration path is not a readable regular file",
            )

    def test_missing_or_blank_database_url_fails_during_composition(self) -> None:
        for configured_value in (None, " \t "):
            with self.subTest(configured_value=configured_value):
                environment = runtime_environment()
                if configured_value is None:
                    environment.pop("ALERT2IR_DATABASE_URL", None)
                else:
                    environment["ALERT2IR_DATABASE_URL"] = configured_value

                self.assert_import_fails(
                    environment,
                    "ALERT2IR_DATABASE_URL must be set and non-empty",
                )

    def test_repository_construction_does_not_connect(self) -> None:
        result = self.run_python(
            "import alert2ir.main",
            runtime_environment(),
        )

        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
