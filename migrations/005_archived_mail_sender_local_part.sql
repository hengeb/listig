-- Fallback for the archive viewer's sender display when a mail's From header has
-- no display name at all (sender_name stays NULL in that case, see
-- ArchiveIndexer::index()) — rather than showing an unhelpful "unknown sender"
-- placeholder, the local part of the sender's address (e.g. "jdoe" from
-- "jdoe@example.com") is shown instead. Deliberately only the local part, never
-- the full address — the archive viewer's own privacy design otherwise never
-- stores or displays a sender's email address (see CLAUDE.md "Privacy" under
-- "Archive viewer"), and a local part alone isn't a deliverable address. Not
-- backfilled — NULL for any row indexed before this migration ran.
ALTER TABLE archived_mail
    ADD COLUMN IF NOT EXISTS sender_local_part VARCHAR(255) NULL;
