<?php

declare(strict_types=1);

namespace Hengeb\Listig\Tests\Archive;

use Hengeb\Listig\Archive\AttachmentSafety;
use PHPUnit\Framework\TestCase;

class AttachmentSafetyTest extends TestCase
{
    /** 1x1 transparent PNG. */
    private const PNG_BYTES_BASE64 = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=';

    public function testRealPngWithCorrectClaimIsSafe(): void
    {
        $png = base64_decode(self::PNG_BYTES_BASE64);
        $this->assertTrue(AttachmentSafety::isSafeInlineContent($png, 'image/png'));
    }

    public function testRealPngMislabeledAsJpegIsStillConsideredSafe(): void
    {
        // Documents actual behavior, not necessarily ideal behavior: the check is
        // "claimed type is in the allowlist AND the real decoded type is *also*
        // in the allowlist" — it does not cross-check that the two match each
        // other. A PNG claimed as image/jpeg therefore still passes, since both
        // are individually on the safe list. Only a type genuinely outside the
        // allowlist (real or claimed) is rejected — see the other tests below.
        $png = base64_decode(self::PNG_BYTES_BASE64);
        $this->assertTrue(AttachmentSafety::isSafeInlineContent($png, 'image/jpeg'));
    }

    public function testNonImageBytesClaimingToBeAnImageIsNotSafe(): void
    {
        $this->assertFalse(AttachmentSafety::isSafeInlineContent('not actually an image', 'image/png'));
    }

    public function testValidPdfMagicBytesIsSafe(): void
    {
        $this->assertTrue(AttachmentSafety::isSafeInlineContent('%PDF-1.4 rest of a fake pdf', 'application/pdf'));
    }

    public function testContentWithoutPdfMagicBytesClaimingPdfIsNotSafe(): void
    {
        $this->assertFalse(AttachmentSafety::isSafeInlineContent('not a pdf at all', 'application/pdf'));
    }

    public function testSvgIsNeverSafeRegardlessOfContent(): void
    {
        // SVG can carry scripts — deliberately never in the allowlist at all.
        $this->assertFalse(AttachmentSafety::isSafeInlineContent('<svg></svg>', 'image/svg+xml'));
    }

    public function testArbitraryMimeTypeIsNotSafe(): void
    {
        $this->assertFalse(AttachmentSafety::isSafeInlineContent('data', 'application/octet-stream'));
    }

    public function testClaimedMimeTypeComparisonIsCaseInsensitive(): void
    {
        $this->assertTrue(AttachmentSafety::isSafeInlineContent('%PDF-fake', 'APPLICATION/PDF'));
    }

    public function testSanitizeFilenameStripsCrLfAndQuotes(): void
    {
        $this->assertSame('evilname.txt', AttachmentSafety::sanitizeFilename("evil\r\nname\".txt"));
    }

    public function testSanitizeFilenameLeavesNormalFilenameUnchanged(): void
    {
        $this->assertSame('report-2026.pdf', AttachmentSafety::sanitizeFilename('report-2026.pdf'));
    }
}
