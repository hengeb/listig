<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Queue\SpamRejectionDetector;

/**
 * Classifies an already-parsed bounce (its RFC 3464 Diagnostic-Code/Status
 * text and the address delivery failed for) into a BounceCause an automatic
 * action exists for in BounceHandler, or null if none applies — the
 * overwhelmingly common case, since most bounces (mailbox full, temporary
 * failure, greylisting, ...) get no automatic action at all, exactly as
 * before this existed.
 *
 * Ordered checks, one per cause, mirroring IncomingMailFilter's own
 * check-order idiom — only a spam check exists today. See BounceCause's own
 * docblock for how a future cause is added.
 */
final class BounceCauseClassifier
{
    public function __construct(
        private readonly SpamRejectionDetector $spamRejectionDetector,
    ) {
    }

    public function classify(?string $reason, ?string $failedRecipient): ?BounceCause
    {
        if ($this->isSpam($reason, $failedRecipient)) {
            return BounceCause::Spam;
        }

        return null;
    }

    /**
     * Same trust boundary as the synchronous SpamRejectionDetector::isSpamRejection()
     * — a "spam" verdict is only actionable when the address delivery failed
     * for belongs to a domain SpamRejectionDetector already trusts to have an
     * authoritative "this is spam" verdict (SpamRejectionDetector::BUILTIN_DOMAINS
     * / the optional reliable-spam-reporters: config.yml key). Without this
     * gate, a forged or misconfigured bounce could be used to make Listig
     * abort delivery of mail — to recipients — it has nothing to do with.
     */
    private function isSpam(?string $reason, ?string $failedRecipient): bool
    {
        if ($reason === null || $failedRecipient === null) {
            return false;
        }

        if (!SpamRejectionDetector::containsSpamIndicator($reason)) {
            return false;
        }

        return $this->spamRejectionDetector->isReliableDomain($failedRecipient);
    }
}
