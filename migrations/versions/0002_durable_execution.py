"""Persist logical processing before external execution."""

from alembic import op


revision = "0002_durable_execution"
down_revision = "0001_processing_records"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE processing_records
            DROP CONSTRAINT ck_processing_records_aggregate_coherence,
            ALTER COLUMN decision_outcome DROP NOT NULL,
            ALTER COLUMN policy_id DROP NOT NULL,
            ALTER COLUMN decision_reasons DROP NOT NULL,
            ADD COLUMN idempotency_scope TEXT NULL,
            ADD COLUMN idempotency_key TEXT NULL,
            ADD COLUMN fingerprint_version SMALLINT NULL,
            ADD COLUMN request_fingerprint BYTEA NULL,
            ADD COLUMN state TEXT NULL,
            ADD COLUMN selected_backend TEXT NULL,
            ADD COLUMN updated_at TIMESTAMPTZ NULL,
            ADD COLUMN completed_at TIMESTAMPTZ NULL,
            ADD COLUMN failed_at TIMESTAMPTZ NULL,
            ADD COLUMN error_category TEXT NULL,
            ADD COLUMN error_detail TEXT NULL;

        UPDATE processing_records
        SET state = 'completed',
            updated_at = created_at,
            completed_at = created_at;

        ALTER TABLE processing_records
            ALTER COLUMN state SET NOT NULL,
            ALTER COLUMN updated_at SET NOT NULL,
            ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP,
            ADD CONSTRAINT uq_processing_records_idempotency
                UNIQUE (idempotency_scope, idempotency_key),
            ADD CONSTRAINT ck_processing_records_state
                CHECK (state IN (
                    'accepted', 'planned', 'submitting', 'submitted',
                    'completed', 'failed', 'recovery_required'
                )),
            ADD CONSTRAINT ck_processing_records_idempotency_coherence
                CHECK (
                    (
                        idempotency_scope IS NULL
                        AND idempotency_key IS NULL
                        AND fingerprint_version IS NULL
                        AND request_fingerprint IS NULL
                    )
                    OR
                    (
                        idempotency_scope IS NOT NULL
                        AND idempotency_scope = source
                        AND idempotency_key IS NOT NULL
                        AND fingerprint_version IS NOT NULL
                        AND request_fingerprint IS NOT NULL
                    )
                ),
            ADD CONSTRAINT ck_processing_records_idempotency_key
                CHECK (
                    idempotency_key IS NULL
                    OR (
                        char_length(idempotency_key) BETWEEN 1 AND 128
                        AND idempotency_key ~ '^[!-~]+$'
                    )
                ),
            ADD CONSTRAINT ck_processing_records_fingerprint
                CHECK (
                    request_fingerprint IS NULL
                    OR (
                        fingerprint_version = 1
                        AND octet_length(request_fingerprint) = 32
                    )
                ),
            ADD CONSTRAINT ck_processing_records_lifecycle_strings
                CHECK (
                    (selected_backend IS NULL OR selected_backend !~ '^[[:space:]]*$')
                    AND (error_category IS NULL OR (
                        error_category !~ '^[[:space:]]*$'
                        AND char_length(error_category) <= 256
                    ))
                    AND (error_detail IS NULL OR (
                        error_detail !~ '^[[:space:]]*$'
                        AND char_length(error_detail) <= 256
                    ))
                    AND (
                        (error_category IS NULL AND error_detail IS NULL)
                        OR
                        (error_category IS NOT NULL AND error_detail IS NOT NULL)
                    )
                ),
            ADD CONSTRAINT ck_processing_records_lifecycle_coherence
                CHECK (
                    (
                        state = 'accepted'
                        AND decision_outcome IS NULL
                        AND policy_id IS NULL
                        AND decision_reasons IS NULL
                        AND request_desired_outcome IS NULL
                        AND request_capabilities IS NULL
                        AND request_targets IS NULL
                        AND selected_backend IS NULL
                        AND result_backend IS NULL
                        AND result_completed_capabilities IS NULL
                        AND result_evidence IS NULL
                        AND completed_at IS NULL
                        AND failed_at IS NULL
                        AND error_category IS NULL
                        AND error_detail IS NULL
                    )
                    OR
                    (
                        state IN ('planned', 'submitting', 'submitted', 'recovery_required')
                        AND decision_outcome = 'investigate'
                        AND policy_id IS NOT NULL
                        AND decision_reasons IS NOT NULL
                        AND jsonb_typeof(decision_reasons) = 'array'
                        AND jsonb_array_length(decision_reasons) > 0
                        AND request_desired_outcome IS NOT NULL
                        AND request_capabilities IS NOT NULL
                        AND jsonb_typeof(request_capabilities) = 'array'
                        AND jsonb_array_length(request_capabilities) > 0
                        AND request_targets IS NOT NULL
                        AND jsonb_typeof(request_targets) = 'array'
                        AND selected_backend IS NOT NULL
                        AND result_backend IS NULL
                        AND result_completed_capabilities IS NULL
                        AND result_evidence IS NULL
                        AND completed_at IS NULL
                        AND failed_at IS NULL
                        AND (
                            state != 'recovery_required'
                            OR (error_category IS NOT NULL AND error_detail IS NOT NULL)
                        )
                    )
                    OR
                    (
                        state = 'completed'
                        AND decision_outcome IN ('investigate', 'no_action')
                        AND policy_id IS NOT NULL
                        AND decision_reasons IS NOT NULL
                        AND jsonb_typeof(decision_reasons) = 'array'
                        AND jsonb_array_length(decision_reasons) > 0
                        AND completed_at IS NOT NULL
                        AND failed_at IS NULL
                        AND (
                            (
                                decision_outcome = 'no_action'
                                AND request_desired_outcome IS NULL
                                AND request_capabilities IS NULL
                                AND request_targets IS NULL
                                AND selected_backend IS NULL
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
                                AND (
                                    selected_backend IS NOT NULL
                                    OR idempotency_key IS NULL
                                )
                                AND result_backend IS NOT NULL
                                AND result_completed_capabilities IS NOT NULL
                                AND jsonb_typeof(result_completed_capabilities) = 'array'
                                AND result_evidence IS NOT NULL
                                AND jsonb_typeof(result_evidence) = 'array'
                            )
                        )
                    )
                    OR
                    (
                        state = 'failed'
                        AND completed_at IS NULL
                        AND failed_at IS NOT NULL
                        AND result_backend IS NULL
                        AND result_completed_capabilities IS NULL
                        AND result_evidence IS NULL
                        AND error_category IS NOT NULL
                        AND error_detail IS NOT NULL
                    )
                );

        CREATE INDEX ix_processing_records_state_updated
            ON processing_records (state, updated_at);

        CREATE TABLE execution_attempts (
            attempt_id UUID PRIMARY KEY,
            processing_id UUID NOT NULL REFERENCES processing_records(id),
            attempt_number INTEGER NOT NULL,
            operation_key UUID NOT NULL UNIQUE,
            backend TEXT NOT NULL,
            state TEXT NOT NULL,
            external_operation_id TEXT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMPTZ NULL,
            submitted_at TIMESTAMPTZ NULL,
            last_polled_at TIMESTAMPTZ NULL,
            completed_at TIMESTAMPTZ NULL,
            failed_at TIMESTAMPTZ NULL,
            last_remote_state TEXT NULL,
            error_category TEXT NULL,
            error_detail TEXT NULL,

            CONSTRAINT uq_execution_attempts_number
                UNIQUE (processing_id, attempt_number),
            CONSTRAINT ck_execution_attempts_number
                CHECK (attempt_number > 0),
            CONSTRAINT ck_execution_attempts_state
                CHECK (state IN (
                    'planned', 'submitting', 'submitted', 'completed',
                    'failed', 'recovery_required'
                )),
            CONSTRAINT ck_execution_attempts_strings
                CHECK (
                    backend !~ '^[[:space:]]*$'
                    AND (external_operation_id IS NULL OR (
                        external_operation_id !~ '^[[:space:]]*$'
                        AND char_length(external_operation_id) <= 512
                    ))
                    AND (last_remote_state IS NULL OR (
                        last_remote_state !~ '^[[:space:]]*$'
                        AND char_length(last_remote_state) <= 256
                    ))
                    AND (error_category IS NULL OR (
                        error_category !~ '^[[:space:]]*$'
                        AND char_length(error_category) <= 256
                    ))
                    AND (error_detail IS NULL OR (
                        error_detail !~ '^[[:space:]]*$'
                        AND char_length(error_detail) <= 256
                    ))
                    AND (
                        (error_category IS NULL AND error_detail IS NULL)
                        OR
                        (error_category IS NOT NULL AND error_detail IS NOT NULL)
                    )
                ),
            CONSTRAINT ck_execution_attempts_lifecycle_coherence
                CHECK (
                    (
                        state = 'planned'
                        AND started_at IS NULL
                        AND submitted_at IS NULL
                        AND external_operation_id IS NULL
                        AND completed_at IS NULL
                        AND failed_at IS NULL
                    )
                    OR
                    (
                        state = 'submitting'
                        AND started_at IS NOT NULL
                        AND submitted_at IS NULL
                        AND external_operation_id IS NULL
                        AND completed_at IS NULL
                        AND failed_at IS NULL
                    )
                    OR
                    (
                        state = 'submitted'
                        AND started_at IS NOT NULL
                        AND submitted_at IS NOT NULL
                        AND external_operation_id IS NOT NULL
                        AND completed_at IS NULL
                        AND failed_at IS NULL
                    )
                    OR
                    (
                        state = 'completed'
                        AND started_at IS NOT NULL
                        AND submitted_at IS NOT NULL
                        AND external_operation_id IS NOT NULL
                        AND completed_at IS NOT NULL
                        AND failed_at IS NULL
                    )
                    OR
                    (
                        state = 'failed'
                        AND completed_at IS NULL
                        AND failed_at IS NOT NULL
                        AND error_category IS NOT NULL
                        AND error_detail IS NOT NULL
                    )
                    OR
                    (
                        state = 'recovery_required'
                        AND started_at IS NOT NULL
                        AND completed_at IS NULL
                        AND failed_at IS NULL
                        AND error_category IS NOT NULL
                        AND error_detail IS NOT NULL
                    )
                )
        );

        CREATE UNIQUE INDEX uq_execution_attempts_active_processing
            ON execution_attempts (processing_id)
            WHERE state IN ('planned', 'submitting', 'submitted', 'recovery_required');
        CREATE INDEX ix_execution_attempts_state_polled
            ON execution_attempts (state, last_polled_at);
        CREATE INDEX ix_execution_attempts_backend_external
            ON execution_attempts (backend, external_operation_id);
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Alert2IR migrations are forward-only")
