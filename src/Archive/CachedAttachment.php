<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

/**
 * A plain, fully-serializable snapshot of one PhpImap\IncomingMailAttachment —
 * same public property names (name/mimeType/sizeInBytes/disposition/contentId),
 * so ArchiveHtmlSanitizer (duck-types ->disposition/->contentId) and
 * templates/archive/show.latte (->name, ->sizeInBytes|formatBytes) work with
 * either type unchanged. The one real difference: $contents is an eagerly
 * fetched string property here, not a getContents() method — see
 * ArchiveMailCache's docblock for why IncomingMailAttachment itself can't be
 * cached directly (it holds a live IMAP connection reference for lazy fetching).
 * Null $contents means the eager fetch failed when this snapshot was built;
 * ArchiveController::attachment() treats that the same as a live fetch failure.
 */
final class CachedAttachment
{
    public function __construct(
        public readonly ?string $name,
        public readonly ?string $mimeType,
        public readonly ?int $sizeInBytes,
        public readonly ?string $disposition,
        public readonly ?string $contentId,
        public readonly ?string $contents,
    ) {
    }
}
