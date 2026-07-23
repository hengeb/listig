-- Listig initial database schema

-- batch_id groups all queued copies of one original incoming mail together, even
-- though personalization (BodyPersonalizer) makes their MIME — and therefore their
-- id, which is a hash of the MIME — different per recipient. Computed once per
-- incoming mail as sha256(list_cn . ':' . rawIncomingMime), so every recipient's
-- copy of the same original mail shares the same batch_id regardless of
-- personalization. NULL means "no known siblings" (QueueSender never groups by
-- NULL/empty, so rows without one are never accidentally linked to each other).
CREATE TABLE IF NOT EXISTS mail_queue (
    id          VARCHAR(64)  NOT NULL PRIMARY KEY,
    list_cn     VARCHAR(255) NOT NULL,
    batch_id    VARCHAR(64)  NULL,
    mime        LONGTEXT     NOT NULL,
    created_at  DATETIME     NOT NULL,
    INDEX idx_batch_id (batch_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS queue_recipients (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    mail_queue_id   VARCHAR(64)  NOT NULL REFERENCES mail_queue(id),
    envelope_to     VARCHAR(255) NOT NULL,
    attempts        TINYINT UNSIGNED NOT NULL DEFAULT 0,
    last_attempt_at DATETIME     NULL,
    status          ENUM('pending','sent','failed') NOT NULL DEFAULT 'pending',
    error           TEXT         NULL,
    INDEX idx_status (status, last_attempt_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- No token column: accept/reject tokens embed list_cn/imap_uid/imap_uidvalidity and
-- are HMAC-signed (see TokenService), so verifying a reply never needs a DB lookup.
-- This table only tracks that an item is pending moderation and when it was
-- created/last reminded.
CREATE TABLE IF NOT EXISTS moderation_queue (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn          VARCHAR(255)  NOT NULL,
    imap_uid         BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity BIGINT UNSIGNED NOT NULL,
    created_at       DATETIME      NOT NULL,
    reminded_at      DATETIME      NULL,
    UNIQUE KEY uq_list_uid (list_cn, imap_uid, imap_uidvalidity)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS imap_seen (
    id               BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn          VARCHAR(255)  NOT NULL,
    imap_uid         BIGINT UNSIGNED NOT NULL,
    imap_uidvalidity BIGINT UNSIGNED NOT NULL,
    seen_at          DATETIME      NOT NULL,
    UNIQUE KEY uq_list_uid (list_cn, imap_uid, imap_uidvalidity),
    INDEX idx_seen_at (seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS rate_limit (
    id       BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn  VARCHAR(255) NOT NULL,
    sender   VARCHAR(255) NOT NULL,
    sent_at  DATETIME     NOT NULL,
    INDEX idx_sender (list_cn, sender, sent_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS bounce_log (
    id         BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn    VARCHAR(255) NOT NULL,
    sender     VARCHAR(255) NOT NULL,
    subject    VARCHAR(500) NULL,
    bounced_at DATETIME     NOT NULL,
    INDEX idx_list_time (list_cn, bounced_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Optional: for database list provider
CREATE TABLE IF NOT EXISTS list_config (
    name   VARCHAR(255) NOT NULL,
    `key`  VARCHAR(255) NOT NULL,
    value  TEXT,
    PRIMARY KEY (name, `key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Optional: for database member resolver. Only name/mail/is_member/is_owner
-- are reserved/structural (DatabaseMemberResolver reads/writes them by name);
-- firstname/lastname/username/pronoun below are just a sensible starter set,
-- not hardcoded anywhere in code — add, rename, or remove columns freely, and
-- SELECT * picks up whatever exists as a {variable} under its own column name
-- (see CLAUDE.md "Pronoun / salutation personalization").
CREATE TABLE IF NOT EXISTS list_members (
    name       VARCHAR(255) NOT NULL,
    mail       VARCHAR(255) NOT NULL,
    firstname  VARCHAR(255) NULL,
    lastname   VARCHAR(255) NULL,
    username   VARCHAR(255) NULL,
    pronoun    VARCHAR(255) NULL,
    is_member  TINYINT(1)   NOT NULL DEFAULT 1,
    is_owner   TINYINT(1)   NOT NULL DEFAULT 0,
    PRIMARY KEY (name, mail)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Index of archived mail, populated by ArchiveIndexer for lists whose `archive`
-- config is not "off" (see CLAUDE.md "Archive access levels").
--
-- Not keyed by imap_uid/imap_uidvalidity like moderation_queue/imap_seen: an IMAP
-- UID is scoped per folder, and archiving moves the message from INBOX into the
-- "Archive" folder, where it gets a new UID that ImapArchiver never learns. The
-- Message-ID is the only stable key, so the actual body/attachments are
-- re-located on demand (IMAP SEARCH on Message-ID) whenever a single message is
-- opened — this table only serves the list/thread view, never the mail content.
CREATE TABLE IF NOT EXISTS archived_mail (
    id              BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn         VARCHAR(255) NOT NULL,
    message_id      VARCHAR(255) NOT NULL,
    in_reply_to     VARCHAR(255) NULL,
    thread_root     VARCHAR(255) NOT NULL,
    subject         VARCHAR(500) NULL,
    sender_name     VARCHAR(255) NULL,
    mail_date       DATETIME NOT NULL,
    has_attachments TINYINT(1) NOT NULL DEFAULT 0,
    archived_at     DATETIME NOT NULL,
    UNIQUE KEY uq_list_message (list_cn, message_id),
    INDEX idx_list_thread (list_cn, thread_root),
    INDEX idx_list_date (list_cn, mail_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
