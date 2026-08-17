"""Validate tracked repository-relative Markdown links without network access.

The contract checks Git-tracked Markdown and Git-tracked repository targets.
External URLs and heading anchors are deliberately out of scope, and no
network request is made.
"""

from collections import defaultdict
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import unittest
from urllib.parse import unquote, urlsplit


_INLINE_LINK = re.compile(r"!?\[[^\]\n]*\]\((?P<destination>[^)\n]*)\)")
_REFERENCE_DEFINITION = re.compile(
    r"^[ \t]{0,3}\[[^\]\n]+\]:[ \t]*(?P<destination><[^>\n]*>|[^\s\n]+)",
    re.MULTILINE,
)
_FENCE_OPEN = re.compile(r"^[ ]{0,3}(?P<marker>`{3,}|~{3,})")


def _run_git(arguments: list[str], cwd: Path) -> bytes:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        raise AssertionError(
            f"git {' '.join(arguments)} failed with exit "
            f"{completed.returncode}: {stderr or '<no stderr>'}"
        )
    return completed.stdout


def _decode_utf8(value: bytes, context: str) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AssertionError(f"{context} is not valid UTF-8: {error}") from error


def _repository_root() -> Path:
    output = _run_git(
        ["rev-parse", "--show-toplevel"],
        cwd=Path(__file__).resolve().parent,
    )
    root_text = _decode_utf8(output, "git repository root").strip()
    if not root_text:
        raise AssertionError("git rev-parse returned an empty repository root")
    return Path(root_text)


def _tracked_paths(repository_root: Path) -> frozenset[str]:
    output = _run_git(["ls-files", "-z"], cwd=repository_root)
    decoded = _decode_utf8(output, "git tracked-path inventory")
    return frozenset(path for path in decoded.split("\0") if path)


def _tracked_markdown_paths(tracked_paths: frozenset[str]) -> tuple[str, ...]:
    return tuple(
        sorted(
            path
            for path in tracked_paths
            if PurePosixPath(path).suffix == ".md"
        )
    )


def _strip_fenced_code(markdown: str) -> str:
    """Blank simple CommonMark backtick/tilde fences while retaining lines."""
    output = []
    fence_character = None
    fence_length = 0

    for line in markdown.splitlines(keepends=True):
        if fence_character is None:
            opening = _FENCE_OPEN.match(line)
            if opening is None:
                output.append(line)
                continue
            marker = opening.group("marker")
            fence_character = marker[0]
            fence_length = len(marker)
        else:
            closing = re.fullmatch(
                rf"[ ]{{0,3}}{re.escape(fence_character)}"
                rf"{{{fence_length},}}[ \t]*(?:\r?\n)?",
                line,
            )
            if closing is not None:
                fence_character = None
                fence_length = 0

        output.append("\n" if line.endswith(("\n", "\r")) else "")

    return "".join(output)


def _strip_inline_code(markdown: str) -> str:
    """Blank bounded backtick code spans used by the repository's prose."""
    output = []
    for line in markdown.splitlines(keepends=True):
        index = 0
        while index < len(line):
            if line[index] != "`":
                output.append(line[index])
                index += 1
                continue

            marker_end = index
            while marker_end < len(line) and line[marker_end] == "`":
                marker_end += 1
            marker = line[index:marker_end]
            closing = line.find(marker, marker_end)
            if closing == -1:
                output.append(line[index:])
                break

            output.append(" " * (closing + len(marker) - index))
            index = closing + len(marker)

    return "".join(output)


def _destination_token(destination: str) -> str:
    stripped = destination.strip()
    if not stripped:
        return ""
    if stripped.startswith("<"):
        closing = stripped.find(">", 1)
        if closing != -1:
            return stripped[1:closing]
    return stripped.split(maxsplit=1)[0]


def _extract_link_targets(markdown: str) -> tuple[str, ...]:
    navigation_text = _strip_inline_code(_strip_fenced_code(markdown))
    matches = []
    for pattern in (_INLINE_LINK, _REFERENCE_DEFINITION):
        matches.extend(
            (match.start(), _destination_token(match.group("destination")))
            for match in pattern.finditer(navigation_text)
        )
    return tuple(target for _, target in sorted(matches) if target)


def _check_target(
    source_path: str,
    destination: str,
    tracked_paths: frozenset[str],
) -> tuple[str, str | None] | None:
    """Return a resolved local target and optional problem, or None if ignored."""
    try:
        parsed = urlsplit(destination)
    except ValueError as error:
        return destination, f"destination cannot be parsed: {error}"

    # URI destinations and links to a heading in the current document are not
    # repository-relative file navigation. Parsing them never performs I/O.
    if parsed.scheme or parsed.netloc or not parsed.path:
        return None

    path = unquote(parsed.path)
    if path.startswith("/"):
        return path, "absolute paths are not repository-relative"

    resolved = posixpath.normpath(
        posixpath.join(posixpath.dirname(source_path), path)
    )
    if resolved == ".." or resolved.startswith("../"):
        return resolved, f"target resolves outside the repository as {resolved}"

    if resolved in tracked_paths:
        return resolved, None

    prefix = "" if resolved == "." else resolved.rstrip("/") + "/"
    if any(candidate.startswith(prefix) for candidate in tracked_paths):
        return resolved, None

    return (
        resolved,
        f"{resolved} is not tracked and contains no tracked repository content",
    )


def _scan_repository_links() -> tuple[int, int, tuple[tuple[str, str, str], ...]]:
    repository_root = _repository_root()
    tracked_paths = _tracked_paths(repository_root)
    markdown_paths = _tracked_markdown_paths(tracked_paths)
    failures = []
    inspected_targets = 0

    for source_path in markdown_paths:
        try:
            markdown = (repository_root / source_path).read_text(encoding="utf-8")
        except UnicodeDecodeError as error:
            failures.append(
                (source_path, "<document>", f"document is not valid UTF-8: {error}")
            )
            continue

        for destination in _extract_link_targets(markdown):
            checked = _check_target(source_path, destination, tracked_paths)
            if checked is None:
                continue
            inspected_targets += 1
            _, problem = checked
            if problem is not None:
                failures.append((source_path, destination, problem))

    return len(markdown_paths), inspected_targets, tuple(sorted(failures))


def _format_failures(failures: tuple[tuple[str, str, str], ...]) -> str:
    grouped = defaultdict(list)
    for source_path, destination, problem in failures:
        grouped[source_path].append((destination, problem))

    lines = ["broken repository-relative Markdown links:"]
    for source_path in sorted(grouped):
        lines.append(f"{source_path}:")
        for destination, problem in sorted(grouped[source_path]):
            lines.append(f"  {destination} -> {problem}")
    return "\n".join(lines)


class MarkdownLinkParserTests(unittest.TestCase):
    def test_relative_inline_link_and_image_are_extracted(self) -> None:
        markdown = "See [guide](docs/GUIDE.md) and ![map](images/map.png)."

        self.assertEqual(
            _extract_link_targets(markdown),
            ("docs/GUIDE.md", "images/map.png"),
        )

    def test_reference_definition_target_is_extracted(self) -> None:
        markdown = "Use [the guide][guide].\n\n[guide]: ../docs/GUIDE.md#usage\n"

        self.assertEqual(
            _extract_link_targets(markdown),
            ("../docs/GUIDE.md#usage",),
        )

    def test_fenced_code_links_are_ignored(self) -> None:
        markdown = (
            "[visible](docs/visible.md)\n"
            "```markdown\n[hidden](docs/missing.md)\n```\n"
            "~~~text\n[also hidden](docs/missing-too.md)\n~~~\n"
        )

        self.assertEqual(
            _extract_link_targets(markdown),
            ("docs/visible.md",),
        )

    def test_inline_code_link_is_ignored(self) -> None:
        markdown = "`[example](docs/not-navigation.md)` [guide](docs/guide.md)"

        self.assertEqual(_extract_link_targets(markdown), ("docs/guide.md",))


class RepositoryTargetTests(unittest.TestCase):
    def test_fragment_and_query_are_ignored_for_file_resolution(self) -> None:
        tracked = frozenset({"README.md", "docs/guide.md"})

        self.assertEqual(
            _check_target(
                "docs/guide.md",
                "../README.md?view=compact#testing",
                tracked,
            ),
            ("README.md", None),
        )

    def test_external_and_anchor_only_targets_are_ignored(self) -> None:
        tracked = frozenset({"docs/guide.md"})

        for destination in (
            "https://example.com/guide",
            "mailto:security@example.com",
            "data:text/plain,example",
            "#local-heading",
        ):
            with self.subTest(destination=destination):
                self.assertIsNone(
                    _check_target("docs/guide.md", destination, tracked)
                )

    def test_parent_segments_resolve_relative_to_source_document(self) -> None:
        tracked = frozenset({"README.md", "docs/nested/guide.md"})

        self.assertEqual(
            _check_target("docs/nested/guide.md", "../../README.md", tracked),
            ("README.md", None),
        )

    def test_percent_encoded_path_is_decoded(self) -> None:
        tracked = frozenset({"docs/index.md", "docs/My Guide.md"})

        self.assertEqual(
            _check_target("docs/index.md", "My%20Guide.md", tracked),
            ("docs/My Guide.md", None),
        )

    def test_repository_escape_is_rejected(self) -> None:
        tracked = frozenset({"docs/guide.md"})

        resolved, problem = _check_target(
            "docs/guide.md", "../../outside.md", tracked
        )

        self.assertEqual(resolved, "../outside.md")
        self.assertIn("outside the repository", problem)

    def test_absolute_path_is_rejected(self) -> None:
        tracked = frozenset({"docs/guide.md"})

        resolved, problem = _check_target(
            "docs/guide.md", "/etc/passwd", tracked
        )

        self.assertEqual(resolved, "/etc/passwd")
        self.assertIn("not repository-relative", problem)

    def test_directory_target_requires_a_tracked_descendant(self) -> None:
        tracked = frozenset(
            {"docs/guide.md", "observability/README.md", "observability/compose.yaml"}
        )

        self.assertEqual(
            _check_target("docs/guide.md", "../observability/", tracked),
            ("observability", None),
        )

    def test_untracked_file_cannot_satisfy_a_target(self) -> None:
        tracked = frozenset({"docs/guide.md"})

        resolved, problem = _check_target(
            "docs/guide.md", "untracked-local-file.md", tracked
        )

        self.assertEqual(resolved, "docs/untracked-local-file.md")
        self.assertIn("is not tracked", problem)


class DocumentationLinkContractTests(unittest.TestCase):
    def test_all_tracked_markdown_relative_links_resolve(self) -> None:
        markdown_count, _, failures = _scan_repository_links()

        self.assertGreater(
            markdown_count,
            0,
            "git ls-files discovered no tracked Markdown documents",
        )
        if failures:
            self.fail(_format_failures(failures))


if __name__ == "__main__":
    unittest.main()
