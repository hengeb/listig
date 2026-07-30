<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

/**
 * Thrown by ArchiveMailLocator::find() specifically when a full, successful
 * SEARCH ALL scan of the list's archive folder completed without finding a
 * matching Message-ID — i.e. the mail was genuinely removed from the IMAP
 * archive folder since it was indexed, not merely unreachable due to a
 * transient IMAP failure (that case returns null instead, same as before —
 * see ArchiveMailLocator::find()). Distinct from a plain null return so
 * ArchiveController::locateMail() can react by deleting the now-stale
 * archived_mail row (ArchiveIndexer::remove()) instead of leaving a listing
 * entry that can never be opened again.
 */
final class ArchiveMailNotFoundException extends \RuntimeException
{
    public function __construct(
        public readonly string $listName,
        public readonly string $messageId,
    ) {
        parent::__construct("Archived mail not found on IMAP: list={$listName} messageId={$messageId}");
    }
}
