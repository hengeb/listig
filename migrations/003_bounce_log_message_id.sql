-- Lets a bounce_log row be re-located later via ArchiveMailLocator (same lookup
-- ArchiveController already uses for archived_mail rows) — populated once by
-- BounceHandler::logBounce() from the bounce mail's own Message-ID header, so
-- the manage page's bounce table can offer a click-through preview the same
-- way the moderation queue does. NULL for any row logged before this migration
-- (not backfilled) or whose bounce mail had no Message-ID at all.
ALTER TABLE bounce_log
    ADD COLUMN IF NOT EXISTS message_id VARCHAR(255) NULL;
