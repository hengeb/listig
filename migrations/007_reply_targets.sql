-- Backs the masked-sender / masked-both reply-to modes (see CLAUDE.md "Masked
-- reply addresses"): the Reply-To of a distributed mail is
-- `{list->localPart}+r-{TOKEN}@{domain}` instead of the sender's own address,
-- and TOKEN references one row of this table.
--
-- kind = 'member': `target_key` is the member's `username` attribute if the
--   backend has one (LDAP: cn), else the address itself. Resolved live against
--   the list's current members when a reply arrives, so an address change is
--   followed automatically (as long as a username exists).
-- kind = 'external': `target_key` is the address.
--
-- Unique per (list_cn, kind, target_key): the same address on two lists gets two
-- rows, i.e. two distinct tokens — a token is list-specific.
CREATE TABLE IF NOT EXISTS reply_targets (
    id            BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    list_cn       VARCHAR(255) NOT NULL,
    kind          ENUM('member','external') NOT NULL,
    target_key    VARCHAR(255) NOT NULL,
    created_at    DATETIME NOT NULL,
    last_used_at  DATETIME NOT NULL,
    UNIQUE KEY uq_list_target (list_cn, kind, target_key),
    INDEX idx_last_used (last_used_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
