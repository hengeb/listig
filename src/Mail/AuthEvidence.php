<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

/**
 * One piece of proof that a mail really comes from its From domain, found in the trusted
 * Authentication-Results header — which method vouched, and for which domain.
 */
final class AuthEvidence
{
    /** @param string $method `dmarc`, `dkim`, `spf` or `auth` (and later e.g. `arc`) */
    public function __construct(
        public readonly string $method,
        public readonly string $domain,
    ) {
    }
}
