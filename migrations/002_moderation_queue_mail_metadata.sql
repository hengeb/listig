-- Adds the original mail's subject/sender/date to moderation_queue, populated
-- once by ModerationMailer::send() from the already-parsed IncomingMail at the
-- point the item is first queued — mirrors archived_mail's own subject/
-- sender_name/mail_date columns (see 001_initial.sql), so both the moderation
-- mail's body and the manage page's moderation queue table can show this
-- without a live IMAP fetch per item.
ALTER TABLE moderation_queue
    ADD COLUMN IF NOT EXISTS subject VARCHAR(500) NULL,
    ADD COLUMN IF NOT EXISTS sender_name VARCHAR(255) NULL,
    ADD COLUMN IF NOT EXISTS sender_mail VARCHAR(255) NULL,
    ADD COLUMN IF NOT EXISTS mail_date DATETIME NULL;
