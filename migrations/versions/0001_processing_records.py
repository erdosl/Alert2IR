"""Create the completed processing-record aggregate."""

from alembic import op


revision = "0001_processing_records"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE processing_records (
            id UUID PRIMARY KEY,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            snapshot_version SMALLINT NOT NULL DEFAULT 1,

            detection_identifier TEXT NOT NULL,
            detection_name TEXT NULL,
            detected_at TIMESTAMPTZ NOT NULL,

            source TEXT NOT NULL,
            source_alert_id TEXT NULL,

            severity TEXT NOT NULL,

            entities JSONB NOT NULL,
            alert_evidence JSONB NOT NULL,

            decision_outcome TEXT NOT NULL,
            policy_id TEXT NOT NULL,
            decision_reasons JSONB NOT NULL,

            request_desired_outcome TEXT NULL,
            request_capabilities JSONB NULL,
            request_targets JSONB NULL,

            result_backend TEXT NULL,
            result_completed_capabilities JSONB NULL,
            result_evidence JSONB NULL,

            CONSTRAINT ck_processing_records_snapshot_version
                CHECK (snapshot_version = 1),
            CONSTRAINT ck_processing_records_severity
                CHECK (severity IN ('low', 'medium', 'high', 'critical')),
            CONSTRAINT ck_processing_records_decision_outcome
                CHECK (decision_outcome IN ('investigate', 'no_action')),
            CONSTRAINT ck_processing_records_required_strings
                CHECK (
                    detection_identifier !~ '^[[:space:]]*$'
                    AND source !~ '^[[:space:]]*$'
                    AND policy_id !~ '^[[:space:]]*$'
                ),
            CONSTRAINT ck_processing_records_optional_strings
                CHECK (
                    (detection_name IS NULL OR detection_name !~ '^[[:space:]]*$')
                    AND (source_alert_id IS NULL OR source_alert_id !~ '^[[:space:]]*$')
                    AND (
                        request_desired_outcome IS NULL
                        OR request_desired_outcome !~ '^[[:space:]]*$'
                    )
                    AND (result_backend IS NULL OR result_backend !~ '^[[:space:]]*$')
                ),
            CONSTRAINT ck_processing_records_required_json_arrays
                CHECK (
                    jsonb_typeof(entities) = 'array'
                    AND jsonb_typeof(alert_evidence) = 'array'
                    AND jsonb_typeof(decision_reasons) = 'array'
                    AND jsonb_array_length(decision_reasons) > 0
                ),
            CONSTRAINT ck_processing_records_aggregate_coherence
                CHECK (
                    (
                        decision_outcome = 'no_action'
                        AND request_desired_outcome IS NULL
                        AND request_capabilities IS NULL
                        AND request_targets IS NULL
                        AND result_backend IS NULL
                        AND result_completed_capabilities IS NULL
                        AND result_evidence IS NULL
                    )
                    OR
                    (
                        decision_outcome = 'investigate'
                        AND request_desired_outcome IS NOT NULL
                        AND request_capabilities IS NOT NULL
                        AND jsonb_typeof(request_capabilities) = 'array'
                        AND jsonb_array_length(request_capabilities) > 0
                        AND request_targets IS NOT NULL
                        AND jsonb_typeof(request_targets) = 'array'
                        AND result_backend IS NOT NULL
                        AND result_completed_capabilities IS NOT NULL
                        AND jsonb_typeof(result_completed_capabilities) = 'array'
                        AND result_evidence IS NOT NULL
                        AND jsonb_typeof(result_evidence) = 'array'
                    )
                )
        )
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Alert2IR migrations are forward-only")
