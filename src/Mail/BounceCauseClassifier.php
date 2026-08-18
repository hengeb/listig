<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Queue\SpamRejectionDetector;

/**
 * Classifies an already-authenticated bounce's RFC 3464 Diagnostic-Code/
 * Status text into a BounceCause an automatic action exists for in
 * BounceHandler, or null if none applies — the overwhelmingly common case,
 * since most bounces (mailbox full, temporary failure, greylisting, ...) get
 * no automatic action at all, exactly as before this existed.
 *
 * Deliberately pure text classification, nothing else: whether this specific
 * bounce is trustworthy *enough to classify at all* — token-verified
 * recipient, reliable domain, DKIM/null-envelope-authenticated origin — is
 * decided once, generically, in BounceHandler::isAuthenticatedOrigin()
 * *before* this class is ever consulted, since that gate applies uniformly
 * to every cause, not just Spam (see CLAUDE.md "Automatic bounce actions").
 * This class only ever sees a reason string it can already trust.
 *
 * Ordered checks, one per cause, mirroring IncomingMailFilter's own
 * check-order idiom — only a spam check exists today. See BounceCause's own
 * docblock for how a future cause is added.
 */
final class BounceCauseClassifier
{
    public function classify(?string $reason): ?BounceCause
    {
        if ($reason !== null && SpamRejectionDetector::containsSpamIndicator($reason)) {
            return BounceCause::Spam;
        }

        return null;
    }
}
