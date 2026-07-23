<?php

declare(strict_types=1);

namespace Hengeb\Listig\Queue;

use Symfony\Component\Mailer\Exception\TransportExceptionInterface;

/**
 * Detects an SMTP-level "rejected as spam" response from the receiving mail
 * server for a single recipient — symfony/mailer's equivalent of checking
 * PHPMailer's ->ErrorInfo after send() === false: TransportExceptionInterface
 * carries the remote server's response text (getMessage()/getDebug()).
 *
 * Only trusted for a hardcoded allowlist of very large mail providers: a
 * malicious or misconfigured SMTP server could otherwise forge a "spam"
 * response to make Listig discard queued mail for other recipients it has
 * nothing to do with (QueueSender treats a match here as grounds to discard
 * every other queued copy of the same original mail, not just this one
 * recipient). A rejection from one of these providers, on the other hand, is
 * both trustworthy and a strong signal the content is genuinely spammy.
 */
class SpamRejectionDetector
{
    /**
     * Deliberately not configurable via config.yml — this is a trust boundary for
     * treating another party's SMTP response as authoritative, not a per-list setting.
     */
    private const TRUSTED_DOMAINS = [
        'gmail.com', 'googlemail.com',
        'gmx.de', 'gmx.net', 'gmx.at', 'gmx.ch', 'gmx.com',
        'web.de', 't-online.de', 'freenet.de',
        'outlook.com', 'hotmail.com', 'hotmail.de', 'hotmail.co.uk', 'live.com', 'live.de', 'msn.com',
        'icloud.com', 'me.com', 'mac.com',
        'yahoo.com', 'yahoo.de', 'yahoo.co.uk', 'aol.com',
    ];

    public function isSpamRejection(\Throwable $e, string $envelopeTo): bool
    {
        if (!$e instanceof TransportExceptionInterface) {
            return false;
        }

        if (!in_array($this->domainOf($envelopeTo), self::TRUSTED_DOMAINS, true)) {
            return false;
        }

        $text = strtolower($e->getMessage() . ' ' . $e->getDebug());
        return str_contains($text, 'spam');
    }

    public function domainOf(string $email): string
    {
        $at = strrpos($email, '@');
        return $at === false ? '' : strtolower(substr($email, $at + 1));
    }
}
