<?php

declare(strict_types=1);

namespace Hengeb\Listig\Imap;

use Hengeb\Listig\Config\Enum\ArchiveMode;
use Hengeb\Listig\Config\ListConfig;

class ImapArchiver
{
    public function __construct(
        private readonly ImapMailboxFactory $mailboxFactory,
    ) {
    }

    public function archiveOrDelete(ListConfig $list, int $uid): void
    {
        $mailbox = $this->mailboxFactory->getMailbox($list);

        if ($list->archive === ArchiveMode::Off) {
            $mailbox->deleteMail($uid);
            $mailbox->expungeDeletedMails();
            return;
        }

        // Members/Owners/Public/Hidden all store the same way at the IMAP level — they
        // only differ in who may view the archive through the web UI (Http/Controller/
        // ArchiveController.php). This method deliberately does not index into
        // archived_mail itself — see Archive/ArchiveIndexer.php's docblock for why.
        $archiveFolder = $list->archiveFolder;
        try {
            $mailbox->createMailbox($archiveFolder);
        } catch (\Throwable) {
            // Folder may already exist
        }
        $mailbox->moveMail($uid, $archiveFolder);
    }

    public function deleteOldMails(ListConfig $list): void
    {
        if (!$list->isImapConfigured) {
            return;
        }

        $mailbox = $this->mailboxFactory->getMailbox($list);
        $cutoff = new \DateTime('-30 days');

        $uids = $mailbox->searchMailbox('BEFORE ' . $cutoff->format('d-M-Y'));
        foreach ($uids as $uid) {
            try {
                $mailbox->deleteMail($uid);
            } catch (\Throwable $e) {
                error_log("Listig: Failed to delete old IMAP mail UID $uid for list {$list->name}: " . $e->getMessage());
            }
        }
        if (!empty($uids)) {
            $mailbox->expungeDeletedMails();
        }
    }
}
