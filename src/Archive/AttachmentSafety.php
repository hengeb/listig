<?php

declare(strict_types=1);

namespace Hengeb\Listig\Archive;

/**
 * Shared by ArchiveController and ModerationController (see "Moderation: preview
 * pending mail" in CLAUDE.md) — both serve mail attachments straight out of IMAP
 * and must never trust a mail's own Content-Type/Content-Disposition claim before
 * deciding whether it's safe to deliver inline. Kept as one class specifically so
 * a future fix to this logic can't accidentally land in only one of the two
 * call sites.
 */
final class AttachmentSafety
{
    /**
     * MIME types ever eligible for inline (browser-rendered, open-in-new-tab)
     * delivery instead of a forced download — never svg, it can carry scripts.
     * Every one of these the browser can display natively; anything else falls
     * back to a download regardless of what the mail itself claims.
     */
    private const INLINE_SAFE_MIME_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'application/pdf'];

    /**
     * Trusting a mail's own Content-Disposition/MIME claim to decide "safe to serve
     * inline" would let a mislabeled attachment ride along; verify the actual bytes
     * decode as one of the whitelisted types before honoring the claim. Images are
     * verified via getimagesizefromstring() (decodes and reports the real format);
     * PDF has no equivalent lightweight PHP decoder, so its magic-bytes header is
     * checked instead — a lighter guarantee, but %PDF- is specific enough that a
     * mislabeled non-PDF attachment couldn't plausibly start with it by accident.
     */
    public static function isSafeInlineContent(string $contents, string $claimedMimeType): bool
    {
        $claimedMimeType = strtolower($claimedMimeType);
        if (!in_array($claimedMimeType, self::INLINE_SAFE_MIME_TYPES, true)) {
            return false;
        }

        if ($claimedMimeType === 'application/pdf') {
            return str_starts_with($contents, '%PDF-');
        }

        $info = @getimagesizefromstring($contents);
        return $info !== false
            && isset($info['mime'])
            && in_array(strtolower($info['mime']), self::INLINE_SAFE_MIME_TYPES, true);
    }

    public static function sanitizeFilename(string $filename): string
    {
        return str_replace(["\r", "\n", '"'], '', $filename);
    }
}
