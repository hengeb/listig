<?php

declare(strict_types=1);

namespace Hengeb\Listig\Imap;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Crypto\PasswordCrypto;
use PhpImap\Mailbox;

/**
 * Builds and caches PhpImap\Mailbox connections per list, keyed by the imap-*
 * config fingerprint. Shared by ImapPoller and ImapArchiver so processing
 * several mails for the same list within one worker cycle reuses a single
 * IMAP login instead of reconnecting for every poll/archive/delete call.
 *
 * reset() must be called once per worker cycle (see bin/worker.php) so
 * connections don't stay open indefinitely across the process's lifetime,
 * where a dropped/stale connection would otherwise never be retried.
 */
class ImapMailboxFactory
{
    /** @var array<string, Mailbox> */
    private array $cache = [];

    public function __construct(
        private readonly PasswordCrypto $passwordCrypto,
    ) {
    }

    public function getMailbox(ListConfig $list): Mailbox
    {
        $fingerprint = $this->fingerprint($list);
        return $this->cache[$fingerprint] ??= $this->createMailbox($list);
    }

    public function reset(): void
    {
        $this->cache = [];
    }

    /**
     * Absolute (top-level, sibling-of-INBOX) path for $folder — e.g. the archive
     * folder (see ListConfig::$archiveFolder). Needed because PhpImap\Mailbox's
     * own createMailbox($name) always resolves $name *relative to whichever
     * mailbox is currently selected* (INBOX, for every Mailbox this factory
     * hands out — see createMailbox() below), so passing a bare folder name
     * straight through would create it *nested under INBOX* (e.g. "INBOX.Archive")
     * instead of as its own top-level folder — silently different from what
     * moveMail()/switchMailbox(..., true) (both used elsewhere for this same
     * folder, and both correctly absolute) then look for, which is exactly the
     * "Could not move messages!" failure this method exists to avoid. Building
     * the full connection-string path ourselves and passing it to the low-level
     * PhpImap\Imap::createmailbox() directly (see ImapArchiver::archiveOrDelete())
     * sidesteps Mailbox's relative-path assembly entirely.
     */
    public function getAbsoluteFolderPath(ListConfig $list, string $folder): string
    {
        return $this->connectionPrefix($list) . $folder;
    }

    private function fingerprint(ListConfig $list): string
    {
        return hash('sha256', implode(':', [
            $list->imapHost,
            $list->imapPort,
            $list->imapUser,
            $list->imapSecure,
        ]));
    }

    private function connectionPrefix(ListConfig $list): string
    {
        $secure = match ($list->imapSecure) {
            'ssl' => '/ssl',
            'tls' => '/tls',
            default => '/notls',
        };

        return "{{$list->imapHost}:{$list->imapPort}/imap{$secure}}";
    }

    private function createMailbox(ListConfig $list): Mailbox
    {
        return new Mailbox(
            $this->connectionPrefix($list) . 'INBOX',
            $list->imapUser,
            $this->passwordCrypto->decryptIfEncrypted($list->imapPassword),
        );
    }
}
