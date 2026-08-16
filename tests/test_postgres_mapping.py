import unittest
from unittest.mock import MagicMock, call, patch

from alert2ir.persistence.postgres import (
    PostgresProcessingRepository,
    SCHEMA_REVISION,
    _decode_entities,
    _decode_evidence,
    _decode_strings,
    _deserialize_row,
    _encode_entities,
    _encode_evidence,
)
from alert2ir.core import Entity, EvidenceReference


class SnapshotV1MappingTests(unittest.TestCase):
    def test_repository_rejects_blank_url(self) -> None:
        with self.assertRaisesRegex(ValueError, "database_url must be non-empty"):
            PostgresProcessingRepository(" \t\n ")

    def test_readiness_is_bounded_and_checks_connectivity_and_schema(self) -> None:
        connection = MagicMock()
        connection.__enter__.return_value = connection
        cursor = connection.cursor.return_value
        cursor.__enter__.return_value = cursor
        cursor.fetchone.return_value = (1,)
        cursor.fetchall.return_value = [(SCHEMA_REVISION,)]

        with patch(
            "alert2ir.persistence.postgres.psycopg.connect",
            return_value=connection,
        ) as connect:
            PostgresProcessingRepository("postgresql://synthetic").check_readiness()

        connect.assert_called_once_with(
            "postgresql://synthetic",
            connect_timeout=3,
            options="-c statement_timeout=2000",
        )
        self.assertEqual(
            cursor.execute.call_args_list,
            [call("SELECT 1"), call("SELECT version_num FROM alembic_version")],
        )

    def test_readiness_rejects_missing_or_unexpected_schema_revision(self) -> None:
        for revisions in ([], [("future_revision",)]):
            with self.subTest(revisions=revisions):
                connection = MagicMock()
                connection.__enter__.return_value = connection
                cursor = connection.cursor.return_value
                cursor.__enter__.return_value = cursor
                cursor.fetchone.return_value = (1,)
                cursor.fetchall.return_value = revisions

                with patch(
                    "alert2ir.persistence.postgres.psycopg.connect",
                    return_value=connection,
                ), self.assertRaisesRegex(
                    RuntimeError,
                    "schema is not at the required revision",
                ):
                    PostgresProcessingRepository(
                        "postgresql://synthetic"
                    ).check_readiness()

    def test_entity_shape_and_order_are_explicit(self) -> None:
        entities = (Entity("host", "workstation-7"), Entity("user", "alice"))

        snapshot = _encode_entities(entities)

        self.assertEqual(
            snapshot,
            [
                {"kind": "host", "value": "workstation-7"},
                {"kind": "user", "value": "alice"},
            ],
        )
        self.assertEqual(_decode_entities(snapshot, "entities"), entities)

    def test_evidence_shape_includes_explicit_null_kind_and_preserves_order(self) -> None:
        evidence = (
            EvidenceReference("record-100", "synthetic-record"),
            EvidenceReference("record-101", None),
        )

        snapshot = _encode_evidence(evidence)

        self.assertEqual(
            snapshot,
            [
                {"reference": "record-100", "kind": "synthetic-record"},
                {"reference": "record-101", "kind": None},
            ],
        )
        self.assertEqual(_decode_evidence(snapshot, "evidence"), evidence)

    def test_string_tuple_order_survives_decode(self) -> None:
        self.assertEqual(
            _decode_strings(["process.list", "network.connections"], "capabilities"),
            ("process.list", "network.connections"),
        )

    def test_reader_rejects_unsupported_snapshot_version(self) -> None:
        with self.assertRaisesRegex(
            ValueError, "unsupported processing snapshot version: 2"
        ):
            _deserialize_row({"snapshot_version": 2})


if __name__ == "__main__":
    unittest.main()
