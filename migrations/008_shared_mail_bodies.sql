-- ADR-0023: the body of a queued mail is stored once in mail_bodies and shared by every
-- recipient's mail_queue row; the row itself keeps only that recipient's headers.
--
-- Rows queued before this migration keep their complete `mime` and are sent as before; new rows
-- have `mime` NULL and `headers` + `body_id` instead. No backfill.
--
-- Every statement is idempotent (MariaDB commits DDL implicitly, see bin/migrate.php).

CREATE TABLE IF NOT EXISTS mail_bodies (
    id          CHAR(64)    NOT NULL PRIMARY KEY,   -- QueueMime::bodyKey()
    body        LONGBLOB    NOT NULL,
    created_at  DATETIME    NOT NULL                -- refreshed whenever the body is reused, see QueueSender::purgeCompletedEntries()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

ALTER TABLE mail_queue
    MODIFY COLUMN mime LONGTEXT NULL,
    ADD COLUMN IF NOT EXISTS headers MEDIUMTEXT NULL,
    ADD COLUMN IF NOT EXISTS body_id CHAR(64) NULL,
    ADD INDEX IF NOT EXISTS idx_body_id (body_id);
