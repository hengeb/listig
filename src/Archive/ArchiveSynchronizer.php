<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Imap\ImapMailboxFactory;
use PDO;
use PhpImap\Mailbox;

/**
 * Reconciles archived_mail with the list's actual IMAP archive folder —
 * catches a mail added or removed directly on IMAP, outside Listig's own
 * distribute/delete paths (an operator moving or deleting a message by hand,
 * or another mail client touching the folder). Triggered from
 * ArchiveController::index() (opening the archive), throttled via session so
 * it runs at most once every ArchiveController::SYNC_INTERVAL_SECONDS per
 * list, not on every page load.
 *
 * Cost shape, why the throttle is enough: sync() always pays for one
 * SEARCH ALL + FETCH OVERVIEW scan of the archive folder (message_id per
 * message, no body) — the same operation ArchiveMailLocator uses to locate a
 * single mail, measured there at ~550ms for a 20-message folder and growing
 * with folder size (see its own docblock). That scan is unavoidable: it's the
 * only way to detect "one mail deleted, a different one added" (same total
 * count, so a cheap STATUS/COUNT comparison alone can't catch it — see the
 * conversation this class was built from). What it deliberately does *not* do
 * is fetch a full message for anything already correctly indexed — only
 * Message-IDs present on IMAP but missing from archived_mail get a full
 * getMail() fetch (to populate subject/sender/date/attachments via
 * ArchiveIndexer::index()); a Message-ID indexed but no longer on IMAP is
 * just removed (ArchiveIndexer::remove(), no fetch at all).
 */
class ArchiveSynchronizer
{
    public function __construct(
        private readonly ImapMailboxFactory $mailboxFactory,
        private readonly PDO $db,
        private readonly ArchiveIndexer $indexer,
    ) {
    }

    /**
     * @return int number of mails added + removed (0 = already in sync, or the
     *         folder couldn't be read — a transient IMAP failure here must
     *         degrade to "nothing to do" rather than touching the index, same
     *         as ArchiveMailLocator's own failure handling).
     */
    public function sync(ListConfig $list): int
    {
        if (!$list->isImapConfigured) {
            return 0;
        }

        try {
            $mailbox = $this->mailboxFactory->getMailbox($list);
            $mailbox->switchMailbox($list->archiveFolder);
            $imapMessageIds = $this->fetchImapMessageIds($mailbox);
        } catch (\Throwable $e) {
            error_log("Listig: ArchiveSynchronizer failed to read archive folder for list {$list->name}: " . $e->getMessage());
            return 0;
        }

        $dbMessageIds = $this->fetchDbMessageIds($list->name);

        // Keys are Message-IDs on both sides — array_diff_key compares keys
        // only, exactly the "present here but not there" set we need; the
        // differing value types (uid vs. true) on each side don't matter.
        $missingInDb    = array_diff_key($imapMessageIds, $dbMessageIds);
        $missingInImap  = array_diff_key($dbMessageIds, $imapMessageIds);

        foreach ($missingInDb as $messageId => $uid) {
            try {
                $mail = $mailbox->getMail($uid, false);
                $this->indexer->index($list, $mail);
            } catch (\Throwable $e) {
                error_log("Listig: ArchiveSynchronizer failed to index Message-ID $messageId (UID $uid) for list {$list->name}: " . $e->getMessage());
            }
        }

        foreach (array_keys($missingInImap) as $messageId) {
            $this->indexer->remove($list->name, $messageId);
        }

        return count($missingInDb) + count($missingInImap);
    }

    /**
     * Overview scan only (FETCH OVERVIEW, via Mailbox::getMailsInfo()) — same
     * SEARCH ALL + FETCH OVERVIEW approach as ArchiveMailLocator::
     * findUidByMessageId(), including the $disableServerEncoding = true
     * workaround documented there (some servers reject the CHARSET argument
     * imap_search() sends otherwise). No message body is ever transferred here.
     *
     * @return array<string, int> message_id => uid
     */
    private function fetchImapMessageIds(Mailbox $mailbox): array
    {
        $allUids = $mailbox->searchMailbox('ALL', true);
        if (empty($allUids)) {
            return [];
        }

        $result = [];
        foreach ($mailbox->getMailsInfo($allUids) as $info) {
            $messageId = trim($info->message_id ?? '', '<> ');
            if ($messageId !== '') {
                $result[$messageId] = (int) $info->uid;
            }
        }
        return $result;
    }

    /** @return array<string, true> message_id => true (used as a set) */
    private function fetchDbMessageIds(string $listName): array
    {
        $stmt = $this->db->prepare('SELECT message_id FROM archived_mail WHERE list_cn = :list');
        $stmt->execute(['list' => $listName]);
        return array_fill_keys($stmt->fetchAll(PDO::FETCH_COLUMN), true);
    }
}
