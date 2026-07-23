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

    private function fingerprint(ListConfig $list): string
    {
        return hash('sha256', implode(':', [
            $list->imapHost,
            $list->imapPort,
            $list->imapUser,
            $list->imapSecure,
        ]));
    }

    private function createMailbox(ListConfig $list): Mailbox
    {
        $secure = match ($list->imapSecure) {
            'ssl' => '/ssl',
            'tls' => '/tls',
            default => '/notls',
        };

        $connectionString = "{{$list->imapHost}:{$list->imapPort}/imap{$secure}}INBOX";

        return new Mailbox(
            $connectionString,
            $list->imapUser,
            $this->passwordCrypto->decryptIfEncrypted($list->imapPassword),
        );
    }
}
