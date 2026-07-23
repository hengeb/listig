<?php

declare(strict_types=1);

namespace Hengeb\Listig\Imap;

use Hengeb\Listig\Config\ListConfig;
use PDO;
use PhpImap\IncomingMail;

class ImapPoller
{
    public function __construct(
        private readonly PDO $db,
        private readonly ImapMailboxFactory $mailboxFactory,
    ) {
    }

    /**
     * Polls IMAP for unseen messages.
     *
     * @return array<array{uid: int, uidvalidity: int, mime: string, mail: IncomingMail}>
     */
    public function poll(ListConfig $list): array
    {
        if (!$list->isImapConfigured) {
            return [];
        }

        $mailbox = $this->mailboxFactory->getMailbox($list);

        $uidValidity = $mailbox->statusMailbox()->uidvalidity ?? 0;

        $this->handleUidValidityChange($list->name, (int) $uidValidity);

        $allUids = $mailbox->searchMailbox('ALL');
        if (empty($allUids)) {
            return [];
        }

        $seenUids = $this->getSeenUids($list->name, (int) $uidValidity);
        $unseenUids = array_diff($allUids, $seenUids);

        $results = [];
        foreach ($unseenUids as $uid) {
            try {
                $raw = $mailbox->getRawMail($uid, false);
                $mail = $mailbox->getMail($uid, false);
                if ($raw && $mail) {
                    $results[] = [
                        'uid'         => (int) $uid,
                        'uidvalidity' => (int) $uidValidity,
                        'mime'        => $raw,
                        'mail'        => $mail,
                    ];
                }
            } catch (\Throwable $e) {
                error_log("Listig: Failed to fetch IMAP UID $uid for list {$list->name}: " . $e->getMessage());
            }
        }

        return $results;
    }

    /** Fetches raw MIME for a specific UID without marking it as seen. */
    public function fetchByUid(ListConfig $list, int $uid): ?string
    {
        $mailbox = $this->mailboxFactory->getMailbox($list);
        try {
            $raw = $mailbox->getRawMail($uid, false);
            return $raw ?: null;
        } catch (\Throwable $e) {
            error_log("Listig: fetchByUid failed for UID $uid on list {$list->name}: " . $e->getMessage());
            return null;
        }
    }

    /** Fetches a parsed IncomingMail for a specific UID without marking it as seen. */
    public function fetchMailByUid(ListConfig $list, int $uid): ?IncomingMail
    {
        $mailbox = $this->mailboxFactory->getMailbox($list);
        try {
            return $mailbox->getMail($uid, false);
        } catch (\Throwable $e) {
            error_log("Listig: fetchMailByUid failed for UID $uid on list {$list->name}: " . $e->getMessage());
            return null;
        }
    }

    public function markSeen(string $listName, int $uid, int $uidValidity): void
    {
        $stmt = $this->db->prepare(
            'INSERT IGNORE INTO imap_seen (list_cn, imap_uid, imap_uidvalidity, seen_at) VALUES (:list, :uid, :validity, NOW())'
        );
        $stmt->execute(['list' => $listName, 'uid' => $uid, 'validity' => $uidValidity]);
    }

    private function getSeenUids(string $listName, int $uidValidity): array
    {
        $stmt = $this->db->prepare(
            'SELECT imap_uid FROM imap_seen WHERE list_cn = :list AND imap_uidvalidity = :validity'
        );
        $stmt->execute(['list' => $listName, 'validity' => $uidValidity]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    private function handleUidValidityChange(string $listName, int $currentUidValidity): void
    {
        $stmt = $this->db->prepare(
            'SELECT DISTINCT imap_uidvalidity FROM imap_seen WHERE list_cn = :list'
        );
        $stmt->execute(['list' => $listName]);
        $storedValidities = $stmt->fetchAll(PDO::FETCH_COLUMN);

        foreach ($storedValidities as $stored) {
            if ((int) $stored !== $currentUidValidity) {
                error_log("Listig: UIDVALIDITY changed for list $listName (was $stored, now $currentUidValidity). Clearing imap_seen.");
                $delete = $this->db->prepare('DELETE FROM imap_seen WHERE list_cn = :list AND imap_uidvalidity = :validity');
                $delete->execute(['list' => $listName, 'validity' => $stored]);
            }
        }
    }
}
