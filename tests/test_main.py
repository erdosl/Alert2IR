import os
import subprocess
import sys
import unittest


class RuntimeCompositionTests(unittest.TestCase):
    def test_missing_or_blank_database_url_fails_during_composition(self) -> None:
        for configured_value in (None, " \t "):
            with self.subTest(configured_value=configured_value):
                environment = os.environ.copy()
                if configured_value is None:
                    environment.pop("ALERT2IR_DATABASE_URL", None)
                else:
                    environment["ALERT2IR_DATABASE_URL"] = configured_value

                result = subprocess.run(
                    [sys.executable, "-c", "import alert2ir.main"],
                    env=environment,
                    capture_output=True,
                    text=True,
                )

                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "ALERT2IR_DATABASE_URL must be set and non-empty",
                    result.stderr,
                )

    def test_repository_construction_does_not_connect(self) -> None:
        environment = os.environ.copy()
        environment["ALERT2IR_DATABASE_URL"] = (
            "postgresql://unused:unused@database.invalid:5432/unused"
        )

        result = subprocess.run(
            [sys.executable, "-c", "import alert2ir.main"],
            env=environment,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
