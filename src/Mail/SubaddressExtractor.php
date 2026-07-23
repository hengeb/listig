<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use PhpImap\IncomingMail;

/**
 * Extracts the +subaddress portion (if any) from an incoming mail's To/Cc
 * addresses, relative to a list's own mail address — e.g. "alice" for
 * fwd+alice@example.org when $list->mail is fwd@example.org. Used by both
 * IncomingMailFilter (reserved-subaddress rejection) and MailProcessor (the
 * {subaddress} mail-context variable), so both stay in sync by construction.
 */
final class SubaddressExtractor
{
    public static function extract(IncomingMail $mail, ListConfig $list): ?string
    {
        $atPos = strrpos($list->mail, '@');
        if ($atPos === false) {
            return null;
        }
        $localPart = substr($list->mail, 0, $atPos);
        $domain    = substr($list->mail, $atPos + 1);
        if ($localPart === '') {
            return null;
        }

        $pattern = '/^' . preg_quote($localPart, '/') . '\+([^@]+)@' . preg_quote($domain, '/') . '$/i';
        foreach ([...array_keys($mail->to), ...array_keys($mail->cc)] as $address) {
            if (preg_match($pattern, $address, $m)) {
                return $m[1];
            }
        }
        return null;
    }
}
