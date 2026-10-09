-- Reference shape for Member 1 / Member 2 to adopt or expose as a compatible view.
-- Not run automatically: the ingestion owner controls the production schema.
CREATE TABLE IF NOT EXISTS incoming_threats (
    event_id String,
    target_url String,
    timestamp DateTime64(3, 'UTC'),
    semgrep_detected Bool DEFAULT false,
    confidence_score Float64 DEFAULT 0,
    evidence String DEFAULT '',
    action_status String DEFAULT 'PENDING',
    proof_url String DEFAULT '',
    ingested_at DateTime64(3, 'UTC') DEFAULT now64(3),
    scan_completed_at Nullable(DateTime64(3, 'UTC')) DEFAULT NULL,
    scanner LowCardinality(String) DEFAULT '',
    run_id String,
    domain String DEFAULT '',
    ip_address String DEFAULT '',
    threat_type LowCardinality(String) DEFAULT ''
) ENGINE = MergeTree ORDER BY (run_id, ingested_at, event_id);
-- Preserve ingestion time when writing scan results. Use unique event_id per run.
-- action_status/proof_url remain the shared-contract fields; dashboard displays actions ledger instead.
