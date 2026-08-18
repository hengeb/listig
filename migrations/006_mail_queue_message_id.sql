-- Original incoming mail's Message-ID (preserved verbatim on every personalized
-- outgoing copy — see MailProcessor::process()/buildOutgoingEmail()'s header
-- preservation), populated once by QueueWriter::enqueue(). Lets BounceHandler
-- correlate an async bounce (which only ever reports the address that failed,
-- never a mail_queue row or batch_id directly) back to every other still-
-- pending copy of the same original mail via mail_queue.batch_id — see
-- BounceCauseClassifier / CLAUDE.md "Automatic bounce actions". Not
-- backfilled — NULL for any row queued before this migration ran, same
-- precedent as bounce_log.message_id (003) / archived_mail.sender_local_part
-- (005).
ALTER TABLE mail_queue
    ADD COLUMN IF NOT EXISTS message_id VARCHAR(255) NULL,
    ADD INDEX IF NOT EXISTS idx_list_message_id (list_cn, message_id);
