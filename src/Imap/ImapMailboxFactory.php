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
 * The cache now also survives *across* worker cycles — bin/worker.php no
 * longer calls reset() at the end of every cycle (see its own comment at
 * that former call site). A cached connection that has since died (server-
 * side idle timeout, a dropped TCP session, a restarted IMAP server, ...) is
 * instead detected and transparently replaced by getMailbox() itself, via a
 * cheap liveness check — see its docblock. This is what makes dropping the
 * per-cycle reset() safe: the original concern reset() existed for ("a
 * dropped/stale connection would otherwise never be retried") is now handled
 * precisely at the point a stale connection would actually cause a problem,
 * rather than defensively rebuilding every connection on a fixed schedule
 * regardless of whether it was ever actually broken. The practical payoff is
 * fewer LOGIN/TLS handshakes against the IMAP server: a healthy connection
 * now survives indefinitely across cycles, and only a genuinely dead one
 * pays the cost of reconnecting.
 */
class ImapMailboxFactory
{
    /** @var array<string, Mailbox> */
    private array $cache = [];

    public function __construct(
        private readonly PasswordCrypto $passwordCrypto,
    ) {
    }

    /**
     * Returns the cached Mailbox for $list's imap-* fingerprint, reconnecting
     * first if the cached connection has died since it was last used.
     *
     * The liveness check is Mailbox::hasImapStream() — a thin wrapper around
     * imap_ping() on the connection's own already-open stream (see php-imap's
     * source: `is_resource($this->imapStream) && imap_ping($this->imapStream)`).
     * This was chosen deliberately over the alternatives available:
     * - Mailbox::getImapStream() (the default, $forceConnection = true) would
     *   itself transparently ping-and-reconnect internally — but as a side
     *   effect of *any* call, including ones this class has no reason to
     *   make just to check liveness, and it reconnects *the same* PHP object
     *   in place rather than letting getMailbox() replace the cache entry
     *   with a fresh one — see the cross-cycle folder-selection note below
     *   for why replacing the object, not just its stream, matters here.
     * - A real no-op IMAP command (e.g. re-running statusMailbox()) would be
     *   a genuine round trip doing actual protocol work — more than "is the
     *   socket still open", and exactly the SELECT/SEARCH-weight check the
     *   task this was built against explicitly wanted to avoid.
     * hasImapStream() is the one option that is both a real liveness check
     * (not just "was a resource ever assigned") and free of side effects
     * when the connection is fine, so it never disturbs a healthy cached
     * Mailbox just by asking.
     *
     * A dead connection is discarded from the cache (not repaired in place)
     * and rebuilt via the existing createMailbox() — a fresh Mailbox is
     * always constructed pointing at INBOX (see createMailbox()), which
     * matters beyond just the connection itself: PhpImap\Mailbox tracks
     * which folder is currently selected as mutable state on the *same*
     * object (switchMailbox() rewrites $imapPath in place), and
     * ImapArchiver::pruneArchive() switches the shared cached Mailbox to the
     * list's archive folder and never switches it back. Now that the cache
     * outlives a single cycle, ImapPoller::poll() — always the first
     * IMAP-touching call for a list in every cycle, see bin/worker.php's own
     * loop order — explicitly switches back to INBOX itself at its own
     * start, rather than assuming a shared, possibly-reused Mailbox is
     * already positioned there the way a *freshly constructed* one always
     * was under the old reset()-every-cycle design. Discarding-and-rebuilding
     * here (instead of reconnecting the existing object) is a second,
     * independent safety net for the same class of problem: a brand new
     * Mailbox is always freshly positioned at INBOX by construction, so a
     * reconnect can never inherit a stale non-INBOX selection left over from
     * whatever the dead connection was last used for.
     */
    public function getMailbox(ListConfig $list): Mailbox
    {
        $fingerprint = $this->fingerprint($list);

        $cached = $this->cache[$fingerprint] ?? null;
        if ($cached !== null && !$cached->hasImapStream()) {
            unset($this->cache[$fingerprint]);
        }

        return $this->cache[$fingerprint] ??= $this->createMailbox($list);
    }

    /**
     * Drops every cached connection outright — no longer called once per
     * worker cycle (see the class docblock); getMailbox()'s own per-call
     * liveness check now replaces a dead connection precisely when one is
     * actually encountered, which is strictly more targeted than discarding
     * every list's connection on a fixed schedule regardless of whether it
     * was still healthy. Kept as a manual "start over" escape hatch — e.g.
     * for a future admin action, or a caller that has a specific reason to
     * distrust every cached connection at once rather than one at a time.
     */
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
