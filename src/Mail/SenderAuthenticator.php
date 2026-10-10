<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

/**
 * Decides whether the From address of an incoming mail is authenticated in the
 * DMARC sense, from the own MTA's Authentication-Results header (selected by
 * HeaderFilter::parseAuthResults()): `dmarc=pass`, `auth=pass` (SMTP AUTH at that server, for mail submitted
 * through it),
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
        return $this->assess($headersRaw, $fromAddress, $trustedAuthservIds)->isAuthenticated();
    }

    /**
     * Collects the evidence that $fromAddress is genuine. Each kind of evidence is its own small method
     * over the parsed header, so another kind (ARC, ADR-0024) is one more method and one more line here,
     * not a change to the callers.
     *
     * @param string[] $trustedAuthservIds
     */
    public function assess(string $headersRaw, string $fromAddress, array $trustedAuthservIds = []): AuthAssessment
    {
        $fromDomain = self::domainOf($fromAddress);
        $header = $fromDomain === '' ? null : $this->headerFilter->parseAuthResults($headersRaw, $trustedAuthservIds);
        if ($header === null) {
            return new AuthAssessment([]);
        }

        return new AuthAssessment([
            ...$this->dmarcEvidence($header, $fromDomain),
            ...$this->dkimEvidence($header, $fromDomain),
            ...$this->smtpAuthEvidence($header, $fromDomain),
            ...$this->spfEvidence($header, $fromDomain),
        ]);
    }

    /** `dmarc=pass`; a reported `header.from` must be the domain being judged. @return list<AuthEvidence> */
    private function dmarcEvidence(AuthResultsHeader $header, string $fromDomain): array
    {
        $evidence = [];
        foreach ($header->all('dmarc') as $r) {
            $reported = $r['props']['header.from'] ?? null;
            if ($r['result'] === 'pass' && ($reported === null || $this->organizationalDomain->aligned($reported, $fromDomain))) {
                $evidence[] = new AuthEvidence('dmarc', $reported ?? $fromDomain);
            }
        }
        return $evidence;
    }

    /** A DKIM pass whose signing domain (`header.d`) is aligned with the From domain. @return list<AuthEvidence> */
    private function dkimEvidence(AuthResultsHeader $header, string $fromDomain): array
    {
        $evidence = [];
        foreach ($header->all('dkim') as $r) {
            $d = $r['props']['header.d'] ?? '';
            if ($r['result'] === 'pass' && $d !== '' && $this->organizationalDomain->aligned($d, $fromDomain)) {
                $evidence[] = new AuthEvidence('dkim', $d);
            }
        }
        return $evidence;
    }

    /**
     * `auth=pass`: the sender logged in at the receiving MTA itself (SMTP AUTH). For a mail sent through
     * the same server nothing else is evaluated — no SPF, no DKIM verification, no DMARC (the MTA
     * signs it on the way out) — so this is the only evidence there is, and a stronger one than SPF.
     * Still bound to the From domain, like the others: the envelope sender it reports must align.
     *
     * @return list<AuthEvidence>
     */
    private function smtpAuthEvidence(AuthResultsHeader $header, string $fromDomain): array
    {
        $evidence = [];
        foreach ($header->all('auth') as $r) {
            $mailFrom = self::domainOf($r['props']['smtp.mailfrom'] ?? '');
            if ($r['result'] === 'pass' && $mailFrom !== '' && $this->organizationalDomain->aligned($mailFrom, $fromDomain)) {
                $evidence[] = new AuthEvidence('auth', $mailFrom);
            }
        }
        return $evidence;
    }

    /** An SPF pass whose envelope sender domain (`smtp.mailfrom`) is aligned with the From domain. @return list<AuthEvidence> */
    private function spfEvidence(AuthResultsHeader $header, string $fromDomain): array
    {
        $evidence = [];
        foreach ($header->all('spf') as $r) {
            $mailFrom = self::domainOf($r['props']['smtp.mailfrom'] ?? '');
            if ($r['result'] === 'pass' && $mailFrom !== '' && $this->organizationalDomain->aligned($mailFrom, $fromDomain)) {
                $evidence[] = new AuthEvidence('spf', $mailFrom);
            }
        }
        return $evidence;
    }

    /** Domain of "user@domain" (or a bare domain, as SPF reports for an empty local part); lowercase, '' if none. */
    private static function domainOf(string $address): string
    {
        $address = trim($address, " \t<>\"");
        $at = strrpos($address, '@');
        return strtolower($at === false ? $address : substr($address, $at + 1));
    }
}
