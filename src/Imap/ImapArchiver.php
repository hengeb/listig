<?php

declare(strict_types=1);

namespace Hengeb\Listig\Imap;

use Hengeb\Listig\Config\Enum\ArchiveMode;
use Hengeb\Listig\Config\ListConfig;
use PhpImap\Imap;

class ImapArchiver
{
    public function __construct(
        private readonly ImapMailboxFactory $mailboxFactory,
    ) {
    }

    public function archiveOrDelete(ListConfig $list, int $uid): void
    {
        if ($list->archive === ArchiveMode::Off) {
            $this->delete($list, $uid);
            return;
        }

        $mailbox = $this->mailboxFactory->getMailbox($list);

        // Members/Owners/Public/Hidden all store the same way at the IMAP level — they
        // only differ in who may view the archive through the web UI (Http/Controller/
        // ArchiveController.php). This method deliberately does not index into
        // archived_mail itself — see Archive/ArchiveIndexer.php's docblock for why.
        $archiveFolder = $list->archiveFolder;

        // Deliberately bypasses PhpImap\Mailbox::createMailbox() — it resolves the
        // given name *relative to the currently selected mailbox* (INBOX here),
        // which would create e.g. "INBOX.Archive" instead of a top-level "Archive"
        // folder. moveMail() below (and ArchiveMailLocator::find()'s
        // switchMailbox(), which defaults to absolute) both target the top-level
        // folder — see ImapMailboxFactory::getAbsoluteFolderPath() for the full
        // explanation. Using the mismatched nested path here previously failed
        // with "Could not move messages!" on every single archive attempt.
        $absoluteFolderPath = $this->mailboxFactory->getAbsoluteFolderPath($list, $archiveFolder);
        try {
            Imap::createmailbox($mailbox->getImapStream(), $absoluteFolderPath);
        } catch (\Throwable) {
            // Folder may already exist
        }
        $mailbox->moveMail($uid, $archiveFolder);
    }

    /**
     * Deletes outright, ignoring the list's own `archive:` setting entirely —
     * unlike archiveOrDelete(), which only deletes when archive is Off and
     * otherwise moves the mail into the archive folder. Used for mail that's
     * never worth keeping regardless of what the list archives everything else
     * as (currently: a `filters:` spam match — see IncomingMailFilter — a
     * spam-filtered mail sitting in the member-visible-adjacent archive folder
     * forever serves no one).
     */
    public function delete(ListConfig $list, int $uid): void
    {
        $mailbox = $this->mailboxFactory->getMailbox($list);
        $mailbox->deleteMail($uid);
        $mailbox->expungeDeletedMails();
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
