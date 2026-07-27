<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Imap\ImapMailboxFactory;
use PhpImap\IncomingMail;
use PhpImap\Mailbox;

/**
 * Re-locates an archived mail by Message-ID inside the list's IMAP archive
 * folder ($list->archiveFolder, default "Archive" — see ImapArchiver::archiveOrDelete
 * and ListConfig::$archiveFolder) and fetches it — the only place outside Imap/
 * that touches PhpImap\Mailbox directly, mirroring why ImapPoller/ImapArchiver
 * exist as wrappers instead of being called ad hoc.
 *
 * NOTE: PhpImap\Mailbox::switchMailbox() mutates the Mailbox instance cached by
 * ImapMailboxFactory in place (it's the same object, now pointed at the archive
 * folder — not a copy). Harmless within one HTTP request (nothing else needs
 * INBOX in an archive-viewer request), but do not assume a Mailbox obtained from
 * the factory is always on INBOX after this class has touched it.
 */
class ArchiveMailLocator
{
    public function __construct(
        private readonly ImapMailboxFactory $mailboxFactory,
    ) {
    }

    public function find(ListConfig $list, string $messageId): ?IncomingMail
    {
        if (!$list->isImapConfigured) {
            return null;
        }

        // A transient IMAP outage must degrade to "mail unavailable" (same as a
        // message genuinely missing), not a 500 — mirrors ImapPoller::fetchByUid()/
        // fetchMailByUid()'s try/catch-and-log-null pattern.
        try {
            $mailbox = $this->mailboxFactory->getMailbox($list);
            $mailbox->switchMailbox($list->archiveFolder);

            $uid = $this->findUidByMessageId($mailbox, trim($messageId, '<> '));

            if ($uid === null) {
                error_log("Listig: ArchiveMailLocator found no IMAP message for Message-ID $messageId in {$list->archiveFolder} for list {$list->name}");
                return null;
            }

            return $mailbox->getMail($uid, false);
        } catch (\Throwable $e) {
            error_log("Listig: ArchiveMailLocator failed to find Message-ID $messageId for list {$list->name}: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Scans every message's overview (IMAP FETCH) for a matching Message-ID,
     * rather than IMAP SEARCH's HEADER key. Confirmed against a real deployment:
     * some servers (mail.hengeb.de among them) don't implement the HEADER search
     * key at all — "Unknown search criterion: HEADER" — even though it's part of
     * the base IMAP4rev1 spec (RFC 3501); the search fails outright regardless of
     * whether the message exists. `SEARCH ALL` + `FETCH OVERVIEW` (whose
     * `message_id` field is exactly the header value, brackets included) are far
     * more fundamental operations every server actually implements, and this is
     * only ever called for a single-message lookup (opening one archived mail in
     * the web viewer), not a bulk operation — the linear scan is cheap in practice.
     */
    private function findUidByMessageId(Mailbox $mailbox, string $needle): ?int
    {
        $allUids = $mailbox->searchMailbox('ALL', true);
        if (empty($allUids)) {
            return null;
        }

        foreach ($mailbox->getMailsInfo($allUids) as $info) {
            if (trim($info->message_id ?? '', '<> ') === $needle) {
                return (int) $info->uid;
            }
        }

        return null;
    }
}
