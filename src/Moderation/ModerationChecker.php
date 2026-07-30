<?php

declare(strict_types=1);

namespace Hengeb\Listig\Moderation;

use Hengeb\Listig\Imap\ImapPoller;
use Hengeb\Listig\Provider\ListProvider;
use PDO;

class ModerationChecker
{
    public function __construct(
        private readonly PDO $db,
        private readonly ListProvider $listProvider,
        private readonly ModerationMailer $moderationMailer,
        private readonly ImapPoller $imapPoller,
    ) {
    }

    public function checkOverdue(): void
    {
        $stmt = $this->db->query(
            "SELECT id, list_cn, imap_uid, imap_uidvalidity
             FROM moderation_queue
             WHERE created_at < NOW() - INTERVAL 7 DAY
               AND (reminded_at IS NULL OR reminded_at < NOW() - INTERVAL 7 DAY)"
        );

        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $list = $this->listProvider->getList($row['list_cn']);
            if ($list === null) {
                continue;
            }

            $rawMime = $this->imapPoller->fetchByUid($list, (int) $row['imap_uid']);
            $mail = $this->imapPoller->fetchMailByUid($list, (int) $row['imap_uid']);
            if ($rawMime === null || $mail === null) {
                error_log("Listig: Moderation reminder skipped for list {$row['list_cn']} UID {$row['imap_uid']}: mail no longer on IMAP");
                continue;
            }

            $this->moderationMailer->send(
                $list,
                $mail,
                (int) $row['imap_uid'],
                (int) $row['imap_uidvalidity'],
                $rawMime,
            );

            $this->db->prepare(
                'UPDATE moderation_queue SET reminded_at = NOW() WHERE id = :id'
            )->execute(['id' => $row['id']]);
        }
    }
}
