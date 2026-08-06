-- Bounds how many worker cycles bin/worker.php retries the same incoming mail
-- after an exception anywhere in its per-mail processing pipeline (filtering,
-- distribution, bounce/reject/moderation handling), instead of retrying it
-- silently forever. Persisted (not an in-memory counter) so the attempt count
-- survives a worker restart between cycles, same as imap_seen/moderation_queue.
-- Keyed by (list_cn, imap_uid, imap_uidvalidity) like imap_seen/moderation_queue
-- — see ProcessingFailureTracker.
CREATE TABLE IF NOT EXISTS processing_failures (
    id                BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn           VARCHAR(255) NOT NULL,
    imap_uid          BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity  BIGINT UNSIGNED NOT NULL,
    attempts          TINYINT UNSIGNED NOT NULL DEFAULT 0,
    last_error        TEXT NULL,
    first_attempt_at  DATETIME NOT NULL,
    last_attempt_at   DATETIME NOT NULL,
    UNIQUE KEY uq_list_uid (list_cn, imap_uid, imap_uidvalidity)
);
