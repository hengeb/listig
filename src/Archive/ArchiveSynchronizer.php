<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Imap\ImapMailboxFactory;
use PDO;
use PhpImap\Mailbox;

/**
 * Reconciles archived_mail with the list's actual IMAP archive folder —
 * catches a mail removed directly on IMAP, outside Listig's own delete paths
 * (an operator or another mail client deleting a message by hand). Triggered
 * from ArchiveController::index() (opening the archive), throttled via
 * session so it runs at most once every ArchiveController::SYNC_INTERVAL_SECONDS
 * per list, not on every page load.
 *
 * Deliberately one-directional — only removes archived_mail rows for
 * Message-IDs no longer on IMAP, never adds one for a Message-ID found on
 * IMAP but missing from the index. An earlier version of this class did both
 * directions, and that was a real bug: bin/worker.php moves a bounced or
 * rejected mail's raw MIME into the *same* archive folder as a distributed
 * one (ImapArchiver::archiveOrDelete() runs for all three outcomes — see
 * CLAUDE.md "IncomingMailFilter — check order"), but only ever calls
 * ArchiveIndexer::index() for an actual distribute — bounce/reject mail is
 * deliberately kept off the member-facing index (see ArchiveIndexer's own
 * docblock). Nothing on the raw IMAP message distinguishes "this is a
 * distribute Listig just hasn't indexed yet" from "this is a reject/bounce
 * Listig never intended to index" — so add-missing necessarily misclassified
 * every rejected/bounced mail as belonging in the archive the moment someone
 * opened it, confirmed live. Remove-missing has no equivalent ambiguity: a
 * Message-ID indexed but no longer on IMAP should always be removed,
 * regardless of why it disappeared.
 *
 * Cost shape, why the throttle is enough: sync() always pays for one
 * SEARCH ALL + FETCH OVERVIEW scan of the archive folder (message_id per
 * message, no body) — the same operation ArchiveMailLocator uses to locate a
 * single mail, measured there at ~550ms for a 20-message folder and growing
 * with folder size (see its own docblock).
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
     * @return int number of archived_mail rows removed (0 = already in sync,
     *         or the folder couldn't be read — a transient IMAP failure here
     *         must degrade to "nothing to do" rather than touching the index,
     *         same as ArchiveMailLocator's own failure handling).
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
        // only, exactly the "indexed here but not present there" set we need;
        // the differing value types (uid vs. true) on each side don't matter.
        $missingInImap = array_diff_key($dbMessageIds, $imapMessageIds);

        foreach (array_keys($missingInImap) as $messageId) {
            $this->indexer->remove($list->name, $messageId);
        }

        return count($missingInImap);
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
