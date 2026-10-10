<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

/**
 * Result of SenderAuthenticator::assess(): every piece of evidence that the From address is genuine
 * (empty = not authenticated). A list instead of a bare yes/no so that new kinds of evidence — ARC
 * seals of a trusted forwarder, say — are just more entries, and so that a log line or a hint to
 * the owners can say *why* a mail was trusted. See ADR-0024.
 */
final class AuthAssessment
{
    /** @param list<AuthEvidence> $evidence */
    public function __construct(public readonly array $evidence)
    {
    }

    public function isAuthenticated(): bool
    {
        return $this->evidence !== [];
    }
}
