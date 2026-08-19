-- Extends automatic bounce handling (BounceHandler) beyond the existing spam
-- case to also cover "user/mailbox unknown" and "mailbox full" — see CLAUDE.md
-- "Automatic bounce actions".
--
-- retry_not_before: set by QueueSender::markBounced() when a mailbox-full
-- bounce is authenticated, to the point in time (computed per-list, from
-- that list's own bounce-defer-days) before which sendBatch() must not
-- attempt this (list, recipient) pair again. NULL means no deferral is
-- active. Deliberately a per-row timestamp rather than an interval baked
-- into sendBatch()'s own query — that query spans every list in one pass,
-- so it has no way to know which list's own bounce-defer-days should apply;
-- computing the cutoff once, per list, at write time sidesteps that.
ALTER TABLE queue_recipients
    ADD COLUMN IF NOT EXISTS retry_not_before DATETIME NULL,
    ADD INDEX IF NOT EXISTS idx_envelope_retry (envelope_to, retry_not_before);

-- Backs the `restrict` bounce-action: addresses skipped at send time
-- (MailProcessor::resolveRecipients(), via BounceSuppressionList), independent
-- of the list's own ListProvider/MemberResolver backend (LDAP/database/csv/
-- inline) — a dedicated table rather than an extension of the existing,
-- purely config-derived `restricted-members:`/RestrictionList mechanism, see
-- CLAUDE.md "Automatic bounce actions".
CREATE TABLE IF NOT EXISTS bounce_suppressed_members (
    id           BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn      VARCHAR(255) NOT NULL,
    envelope_to  VARCHAR(255) NOT NULL,
    reason       VARCHAR(64)  NOT NULL,
    created_at   DATETIME     NOT NULL,
    UNIQUE KEY uq_list_recipient (list_cn, envelope_to)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
