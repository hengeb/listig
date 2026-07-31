<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

use Hengeb\Listig\Config\ListConfig;
use PhpImap\IncomingMailAttachment;

/**
 * Locate-by-Message-ID + eager-attachment-caching logic shared by
 * ArchiveController and BounceController (see CLAUDE.md "Bounce preview") —
 * both ultimately show a mail that lives in the list's IMAP archive folder,
 * keyed by Message-ID, with the same "several separate HTTP requests for one
 * page view" performance problem ArchiveMailCache exists to solve (see its own
 * docblock). Deliberately does not decide what to do when
 * ArchiveMailNotFoundException is thrown (a confirmed-gone mail) — that cleanup
 * differs per caller (ArchiveController removes the archived_mail row;
 * BounceController has no equivalent index to clean up) — callers catch it
 * themselves.
 */
class ArchiveMailResolver
{
    public function __construct(
        private readonly ArchiveMailLocator $mailLocator,
        private readonly ArchiveMailCache $mailCache,
    ) {
    }

    /** @throws ArchiveMailNotFoundException */
    public function resolve(ListConfig $list, string $messageId): ?CachedArchivedMail
    {
        $cached = $this->mailCache->get($list->name, $messageId);
        if ($cached !== null) {
            return $cached;
        }

        $mail = $this->mailLocator->find($list, $messageId);
        if ($mail === null) {
            return null;
        }

        $attachments = [];
        foreach (self::indexAttachmentsByPosition($mail->getAttachments()) as $index => $attachment) {
            try {
                $contents = $attachment->getContents();
            } catch (\Throwable $e) {
                error_log("Listig: failed to eagerly fetch attachment $index for Message-ID $messageId on list {$list->name}: " . $e->getMessage());
                $contents = null;
            }
            $attachments[$index] = new CachedAttachment(
                $attachment->name,
                $attachment->mimeType,
                $attachment->sizeInBytes,
                $attachment->disposition,
                $attachment->contentId,
                $contents,
            );
        }

        $cached = new CachedArchivedMail($mail->textHtml, $mail->textPlain, $attachments);
        $this->mailCache->set($list->name, $messageId, $cached);

        return $cached;
    }

    /**
     * IncomingMail::getAttachments() is keyed by IncomingMailAttachment::$id —
     * PhpImap\Mailbox generates this fresh with bin2hex(random_bytes(20)) on
     * *every* parse, so it is never the same twice for the same message, let alone
     * stable across the separate HTTP requests this app's routes are split across.
     * Using that random id as the {index} in a URL therefore can never work: by
     * the time attachment() looks it up, the id it's holding no longer exists
     * anywhere.
     *
     * The MIME part order php-imap parses attachments in, by contrast, is fully
     * determined by the message's own (unchanging) byte structure — parsing the
     * same raw mail twice always encounters its attachments in the same order.
     * Re-keying by that position instead of the random id gives every caller a
     * stable identifier that actually survives from one request to the next.
     *
     * @param IncomingMailAttachment[] $attachments
     * @return array<int, IncomingMailAttachment>
     */
    private static function indexAttachmentsByPosition(array $attachments): array
    {
        return array_values($attachments);
    }
}
