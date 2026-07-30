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

    /**
     * One-off connection test with a candidate plaintext password — bypasses
     * both the connection cache and $list->imapPassword entirely, so it never
     * disturbs an already-cached, working connection for this list and never
     * needs the candidate to be encrypted first. Used by
     * ListApiController::encryptPassword() to verify a new password actually
     * logs in *before* persisting it, rather than persisting a typo and only
     * discovering it's wrong on the next poll cycle.
     *
     * @throws \PhpImap\Exceptions\ConnectionException if the login fails (wrong
     *         password, unreachable host, ...) — caller decides how to surface
     *         this; imap_open() itself doesn't distinguish the two, so neither
     *         does this.
     *
     * Deliberately never calls $mailbox->disconnect() itself — Mailbox already
     * does that in its own __destruct(), and calling it twice (once here, once
     * from the destructor moments later) throws "ValueError: IMAP\Connection is
     * already closed" from the second call, confirmed live. No other call site
     * in this codebase calls ->disconnect() either (see ImapMailboxFactory::
     * reset(), which just drops cached Mailbox objects and lets garbage
     * collection trigger the one destructor-driven disconnect) — this method
     * follows the same convention for the same reason.
     */
    public function verifyPassword(ListConfig $list, string $plaintextPassword): void
    {
        $mailbox = new Mailbox(
            $this->connectionPrefix($list) . 'INBOX',
            $list->imapUser,
            $plaintextPassword,
        );
        $mailbox->getImapStream();
    }
}
