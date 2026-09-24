-- Retry-exhausted reports remain incomplete and are retried after a bounded
-- cooldown, so keep them indexed for the worker's due-report scan.
CREATE INDEX host_storage_report_retry_exhausted_idx
    ON host_storage_report (next_attempt_at, received_at)
    WHERE state = 'retry_exhausted';
