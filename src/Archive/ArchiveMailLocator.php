<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Imap\ImapMailboxFactory;
use PhpImap\IncomingMail;

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

            // Strip quotes from attacker-influenced content (the Message-ID ultimately
            // comes from an external sender's header) before interpolating into the
            // IMAP SEARCH command string.
            $needle = str_replace('"', '', $messageId);
            $uids = $mailbox->searchMailbox('HEADER Message-ID "' . $needle . '"');

            if (empty($uids)) {
                return null;
            }

            return $mailbox->getMail((int) $uids[0], false);
        } catch (\Throwable $e) {
            error_log("Listig: ArchiveMailLocator failed to find Message-ID $messageId for list {$list->name}: " . $e->getMessage());
            return null;
        }
    }
}
