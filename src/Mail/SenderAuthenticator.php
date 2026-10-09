<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

/**
 * Decides whether the From address of an incoming mail is authenticated in the
 * DMARC sense, from the own MTA's Authentication-Results header (selected by
 * HeaderFilter::parseAuthResults()): `dmarc=pass`,
 * or a DKIM pass whose `header.d` is aligned with the From domain, or an SPF
 * pass whose `smtp.mailfrom` domain is aligned with it (relaxed alignment, see
 * OrganizationalDomain). Pure logic; no I/O.
 */
class SenderAuthenticator
{
    public function __construct(
        private readonly HeaderFilter $headerFilter,
        private readonly OrganizationalDomain $organizationalDomain,
    ) {
    }

    /** @param string[] $trustedAuthservIds the list's `trusted-authserv-id`; empty = topmost header */
    public function isAuthenticated(string $headersRaw, string $fromAddress, array $trustedAuthservIds = []): bool
    {
        $fromDomain = self::domainOf($fromAddress);
        if ($fromDomain === '') {
            return false;
        }
        $header = $this->headerFilter->parseAuthResults($headersRaw, $trustedAuthservIds);
        if ($header === null) {
            return false;
        }

        foreach ($header->all('dmarc') as $r) {
            // header.from, if reported, must be the domain we are judging.
            $reported = $r['props']['header.from'] ?? null;
            if ($r['result'] === 'pass' && ($reported === null || $this->organizationalDomain->aligned($reported, $fromDomain))) {
                return true;
            }
        }
        foreach ($header->all('dkim') as $r) {
            $d = $r['props']['header.d'] ?? '';
            if ($r['result'] === 'pass' && $d !== '' && $this->organizationalDomain->aligned($d, $fromDomain)) {
                return true;
            }
        }
        foreach ($header->all('spf') as $r) {
            $mailFrom = self::domainOf($r['props']['smtp.mailfrom'] ?? '');
            if ($r['result'] === 'pass' && $mailFrom !== '' && $this->organizationalDomain->aligned($mailFrom, $fromDomain)) {
                return true;
            }
        }
        return false;
    }

    /** Domain of "user@domain" (or a bare domain, as SPF reports for an empty local part); lowercase, '' if none. */
    private static function domainOf(string $address): string
    {
        $address = trim($address, " \t<>\"");
        $at = strrpos($address, '@');
        return strtolower($at === false ? $address : substr($address, $at + 1));
    }
}
