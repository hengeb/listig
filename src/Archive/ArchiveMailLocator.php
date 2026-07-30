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
 *
 * This class always does a full SEARCH ALL + FETCH OVERVIEW scan — it has no
 * caching of its own. ArchiveController::locateMail() is the caller that
 * actually avoids paying for this repeatedly (an APCu-backed cache of the fully
 * rendered mail, see Archive\ArchiveMailCache), so a cache hit there means this
 * class isn't even called at all for a given mail's second/third/... request.
 */
class ArchiveMailLocator
{
    public function __construct(
        private readonly ImapMailboxFactory $mailboxFactory,
    ) {
    }

    /**
     * @throws ArchiveMailNotFoundException when a full, successful SEARCH ALL
     *         scan completed without finding the Message-ID — i.e. the mail is
     *         confirmed gone from the archive folder, not just unreachable
     *         right now. A transient IMAP outage (connect/search/fetch failure)
     *         degrades to a plain null return instead, same as before — mirrors
     *         ImapPoller::fetchByUid()/fetchMailByUid()'s try/catch-and-log-null
     *         pattern. The two are deliberately distinguished so the caller
     *         (ArchiveController::locateMail()) can safely remove the
     *         archived_mail index row on a confirmed miss without risking doing
     *         so on a merely-temporary IMAP hiccup.
     */
    public function find(ListConfig $list, string $messageId): ?IncomingMail
    {
        if (!$list->isImapConfigured) {
            return null;
        }

        $needle = trim($messageId, '<> ');

        try {
            $mailbox = $this->mailboxFactory->getMailbox($list);
            $mailbox->switchMailbox($list->archiveFolder);
            $uid = $this->findUidByMessageId($mailbox, $needle);
        } catch (\Throwable $e) {
            error_log("Listig: ArchiveMailLocator failed to find Message-ID $messageId for list {$list->name}: " . $e->getMessage());
            return null;
        }

        if ($uid === null) {
            error_log("Listig: ArchiveMailLocator found no IMAP message for Message-ID $messageId in {$list->archiveFolder} for list {$list->name} — removing from archive index");
            throw new ArchiveMailNotFoundException($list->name, $messageId);
        }

        try {
            return $mailbox->getMail($uid, false);
        } catch (\Throwable $e) {
            error_log("Listig: ArchiveMailLocator failed to fetch UID $uid (Message-ID $messageId) for list {$list->name}: " . $e->getMessage());
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
     * the web viewer), not a bulk operation — the linear scan is cheap in practice,
     * though its cost does grow with the archive folder's total message count
     * (see ArchiveController::locateMail()'s cache, which is what actually keeps
     * this from being paid repeatedly for the same mail within one page view).
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
