<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

/**
 * A plain, fully-serializable snapshot of everything ArchiveController's
 * show()/frame()/attachment() need from a PhpImap\IncomingMail — see
 * ArchiveMailCache's docblock for why the IncomingMail object itself can't be
 * cached directly. Built once (ArchiveController::locateMail(), on a cache
 * miss) by eagerly resolving every CachedAttachment::$contents up front, while
 * the IMAP connection used to locate the mail is still open.
 */
final class CachedArchivedMail
{
    /** @param CachedAttachment[] $attachments positionally indexed — see ArchiveController::indexAttachmentsByPosition() */
    public function __construct(
        public readonly ?string $textHtml,
        public readonly ?string $textPlain,
        public readonly array $attachments,
    ) {
    }
}
