<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Queue\SpamRejectionDetector;

/**
 * Classifies an already-authenticated bounce's RFC 3464 Diagnostic-Code/
 * Status text into a BounceCause an automatic action exists for in
 * BounceHandler, or null if none applies — the overwhelmingly common case,
 * since most bounces (greylisting, a generic temporary failure, ...) get no
 * automatic action at all, exactly as before this existed.
 *
 * Deliberately pure text classification, nothing else: whether this specific
 * bounce is trustworthy *enough to classify at all* — token-verified
 * recipient, reliable domain, DKIM/null-envelope-authenticated origin, a
 * final (not "delayed") delivery outcome — is decided once, generically, in
 * BounceHandler *before* this class is ever consulted, since that gate
 * applies uniformly to every cause, not just one (see CLAUDE.md "Automatic
 * bounce actions"). This class only ever sees a reason string it can already
 * trust.
 *
 * Ordered checks, one per cause, mirroring IncomingMailFilter's own
 * check-order idiom. See BounceCause's own docblock for how a future cause
 * is added.
 */
final class BounceCauseClassifier
{
    /**
     * Enhanced Status Codes (RFC 3463) for a permanently undeliverable
     * mailbox/domain — checked anywhere in the reason text (not just a
     * leading prefix), since callers pass in a concatenation of
     * Diagnostic-Code and Status and either field's own position varies by
     * MTA. `5.1.x` is the "bad destination mailbox/system address" class
     * (RFC 3463 §3.2); `X.4.3`/`X.4.4` ("directory server failure"/"unable
     * to route", RFC 3463 §3.5) is what Postfix actually emits for a DNS
     * lookup failure on the recipient's domain — confirmed live: a real
     * "Host or domain name not found" bounce carried `Status: 5.4.4` with no
     * status code anywhere in its own Diagnostic-Code text at all, so both
     * fields have to be searched, not just whichever one a specific server
     * happens to make more human-readable. The 4.x variants are included
     * defensively even though `isFinalDeliveryOutcome()` already requires
     * `Action: failed` — a non-conformant server could still report a final
     * outcome under a nominally-"temporary" status class.
     */
    private const array USER_UNKNOWN_STATUS_CODES = [
        '5.1.1', '5.1.2', '5.1.3', '5.1.6', '5.1.10',
        '4.4.3', '5.4.3', '4.4.4', '5.4.4',
    ];

    /** Fallback for a bounce with no clean status code prefix, or one from a non-conformant server. */
    private const array USER_UNKNOWN_KEYWORDS = [
        'user unknown', 'no such user', 'recipient address rejected',
        'mailbox unavailable', 'does not exist', 'unrouteable address',
        'unknown user', 'invalid recipient', 'unknown recipient',
        'host or domain name not found', 'domain name not found',
        'name service error', 'host not found', 'unable to route',
    ];

    private const array MAILBOX_FULL_STATUS_CODES = ['4.2.2', '5.2.2'];

    private const array MAILBOX_FULL_KEYWORDS = ['mailbox full', 'quota exceeded', 'over quota', 'insufficient system storage'];

    public function classify(?string $reason): ?BounceCause
    {
        if ($reason === null) {
            return null;
        }

        if (SpamRejectionDetector::containsSpamIndicator($reason)) {
            return BounceCause::Spam;
        }

        if (self::matchesStatusCode($reason, self::USER_UNKNOWN_STATUS_CODES) || self::containsAny($reason, self::USER_UNKNOWN_KEYWORDS)) {
            return BounceCause::UserUnknown;
        }

        if (self::matchesStatusCode($reason, self::MAILBOX_FULL_STATUS_CODES) || self::containsAny($reason, self::MAILBOX_FULL_KEYWORDS)) {
            return BounceCause::MailboxFull;
        }

        return null;
    }

    /**
     * True if $reason contains one of $codes as a standalone Enhanced Status
     * Code (e.g. "5.1.1"), not merely as a substring of a longer number —
     * word-boundary matched so "5.1.10" (User Unknown, "Recipient address
     * has null MX") isn't accidentally matched by a bare "1.1" search or
     * vice versa.
     */
    private static function matchesStatusCode(string $reason, array $codes): bool
    {
        foreach ($codes as $code) {
            if (preg_match('/(?<![\d.])' . preg_quote($code, '/') . '(?![\d.])/', $reason)) {
                return true;
            }
        }
        return false;
    }

    private static function containsAny(string $reason, array $keywords): bool
    {
        $lower = strtolower($reason);
        foreach ($keywords as $keyword) {
            if (str_contains($lower, $keyword)) {
                return true;
            }
        }
        return false;
    }
}
