<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

/**
 * APCu-backed cache of a fully-resolved archived mail (see CachedArchivedMail),
 * keyed by list + Message-ID. Exists because opening one archived mail in the
 * web viewer fires several separate HTTP requests — show(), frame(), one
 * attachment() request per embedded image — and public/index.php builds a
 * brand new container (so a brand new IMAP connection) on every single one of
 * them; without this cache, each independently re-runs ArchiveMailLocator's
 * full IMAP connect + SEARCH ALL + FETCH OVERVIEW scan of the *entire* archive
 * folder just to re-locate the same one message (measured live: ~550ms per
 * call against a 20-message archive folder — and the scan cost grows with the
 * folder's total message count, not just this one mail).
 *
 * Deliberately APCu, not a per-session cache (an earlier version of this class
 * used $_SESSION) — shared in-memory storage across every php-fpm worker in
 * this container (not just one browser session, so a second viewer opening the
 * same archived mail benefits too), automatically TTL-evicted with no manual
 * cleanup needed, and never touches disk (unlike PHP's default file-based
 * session handler) — a closer match to this codebase's existing "nothing
 * cached to disk" stance on mail content than a session-file-backed cache
 * would have been.
 *
 * Why this caches a CachedArchivedMail snapshot rather than the
 * PhpImap\IncomingMail object itself: IncomingMail's attachments
 * (IncomingMailAttachment::$dataInfo, a DataPartInfo) hold a live reference to
 * the PhpImap\Mailbox/IMAP connection that produced them — getContents()
 * fetches lazily over that connection on demand. A PHP resource/IMAP
 * connection cannot survive serialization (apcu_store() serializes non-scalar
 * values internally), and even if it silently didn't error, the connection
 * would already be closed by the time a *different* request tried to use a
 * cached attachment. CachedArchivedMail/CachedAttachment are the eagerly
 * resolved, plain-data equivalent built once while the connection is still open.
 */
class ArchiveMailCache
{
    /**
     * Long enough to cover one page view (show() + frame() + every embedded
     * image's attachment() request) comfortably, short enough to bound shared
     * memory usage — archived mail content never changes once archived, so
     * there's no correctness reason to expire sooner than that; this is purely
     * a memory-footprint choice, not a staleness one.
     */
    private const TTL_SECONDS = 300;

    private const PREFIX = 'listig:archive_mail:';

    /**
     * True only when the apcu extension is both loaded and actually usable in
     * this SAPI (apcu_enabled() is false for CLI unless apc.enable_cli=1 — see
     * docker/php.ini). Checked once per instance rather than per call; nothing
     * here ever fatals if it's false, get() just always misses and set() is a
     * silent no-op — the archive viewer still works, just without this
     * optimization, exactly as it did before this class existed.
     */
    private readonly bool $enabled;

    public function __construct()
    {
        $this->enabled = function_exists('apcu_enabled') && apcu_enabled();
    }

    public function get(string $listName, string $messageId): ?CachedArchivedMail
    {
        if (!$this->enabled) {
            return null;
        }
        $value = apcu_fetch($this->key($listName, $messageId), $success);
        return $success && $value instanceof CachedArchivedMail ? $value : null;
    }

    public function set(string $listName, string $messageId, CachedArchivedMail $mail): void
    {
        if (!$this->enabled) {
            return;
        }
        apcu_store($this->key($listName, $messageId), $mail, self::TTL_SECONDS);
    }

    /**
     * Invalidates a cached snapshot right after the underlying mail was deleted
     * (see ArchiveController::delete()) — without this, a viewer who opened the
     * mail moments before deletion would keep seeing the cached copy for up to
     * TTL_SECONDS, even though it no longer exists on IMAP or in the archived_mail
     * index.
     */
    public function delete(string $listName, string $messageId): void
    {
        if (!$this->enabled) {
            return;
        }
        apcu_delete($this->key($listName, $messageId));
    }

    private function key(string $listName, string $messageId): string
    {
        return self::PREFIX . $listName . ':' . hash('sha256', trim($messageId, '<> '));
    }
}
