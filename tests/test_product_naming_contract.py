"""Prevent internal development chronology from re-entering product identity."""

from pathlib import Path
import re
import subprocess
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEVELOPMENT_IDENTIFIER = re.compile(
    r"\b" + "ws" + r"[0-9]+\b"
    r"|\b" + "phase" + r"[ \t_-]*[0-9]+\b"
    r"|\b" + "stage" + r"[ \t_-]*[0-9]+\b"
    r"|\b" + "work" + "stream" + r"\b"
    r"|" + "alert2ir-" + "ws",
    re.IGNORECASE,
)
SPELLED_DEVELOPMENT_IDENTIFIER = re.compile(
    r"\b(?:" + "phase" + "|" + "stage" + r")[ _-]*"
    r"(?:one|two|three|four|five|six|seven|eight|nine)\b",
    re.IGNORECASE,
)


def current_repository_files() -> list[Path]:
    """Return present tracked and candidate files, excluding ignored state."""
    completed = subprocess.run(
        [
            "git",
            "ls-files",
            "-co",
            "--exclude-standard",
            "-z",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        stdout=subprocess.PIPE,
    )
    return sorted(
        path
        for item in completed.stdout.split(b"\0")
        if item
        if (path := REPOSITORY_ROOT / item.decode("utf-8")).is_file()
    )


class ProductNamingContractTests(unittest.TestCase):
    def test_present_repository_paths_have_functional_names(self) -> None:
        offending = [
            path.relative_to(REPOSITORY_ROOT).as_posix()
            for path in current_repository_files()
            if DEVELOPMENT_IDENTIFIER.search(path.relative_to(REPOSITORY_ROOT).as_posix())
            or SPELLED_DEVELOPMENT_IDENTIFIER.search(
                path.relative_to(REPOSITORY_ROOT).as_posix()
            )
        ]
        self.assertEqual(offending, [])

    def test_present_repository_text_has_no_development_identifiers(self) -> None:
        offending: list[str] = []
        for path in current_repository_files():
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for line_number, line in enumerate(text.splitlines(), start=1):
                if DEVELOPMENT_IDENTIFIER.search(
                    line
                ) or SPELLED_DEVELOPMENT_IDENTIFIER.search(line):
                    offending.append(
                        f"{path.relative_to(REPOSITORY_ROOT).as_posix()}:{line_number}"
                    )
        self.assertEqual(offending, [])


if __name__ == "__main__":
    unittest.main()
