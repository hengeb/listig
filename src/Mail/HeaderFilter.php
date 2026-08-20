<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

class HeaderFilter
{
    /**
     * Unfolds RFC 2822 header folding (CRLF followed by whitespace) so a header's
     * value can be matched with a single-line regex regardless of how the sending
     * MTA wrapped it. Shared by IncomingMailFilter and MailProcessor, which both
     * need to scan raw header blocks for specific header lines.
     */
    public function unfold(string $headersRaw): string
    {
        return preg_replace('/\r?\n[ \t]+/', ' ', $headersRaw);
    }

    /**
     * Reads a single header's value out of a raw header block, unfolding first so a
     * wrapped value still matches. Returns the first occurrence, or null if absent.
     * Shared by MailProcessor (preserving Message-ID/In-Reply-To/References/Date on
     * the outgoing mail) and ArchiveIndexer (threading headers for the archive view).
     */
    public function readHeader(string $headersRaw, string $name): ?string
    {
        $unfolded = $this->unfold($headersRaw);
        if (preg_match('/^' . preg_quote($name, '/') . ':\s*(.+)$/mi', $unfolded, $m)) {
            return trim($m[1]);
        }
        return null;
    }

    /**
     * Bare Message-ID (no surrounding `<>`) — same normalization ArchiveIndexer
     * applies before storing one, so a value read here always matches what
     * ArchiveMailLocator::find()/ArchiveIndexer::index() key their own lookups
     * by. Used by BounceHandler to record which archived_mail-equivalent entry
     * (bounce_log.message_id) a bounce can later be re-located by, the same way
     * a distributed mail is keyed by its own Message-ID.
     */
    public function readMessageId(string $headersRaw): ?string
    {
        $value = $this->readHeader($headersRaw, 'Message-ID');
        if ($value === null) {
            return null;
        }
        $value = trim($value, '<> ');
        return $value === '' ? null : $value;
    }

    /**
     * Parses SPF and DKIM results from the Authentication-Results header(s)
     * in a raw header block.
     *
     * @return array{spf: string|null, dkim: string|null, dkimDomain: string|null}
     */
    public function readAuthResults(string $headersRaw): array
    {
        $unfolded = $this->unfold($headersRaw);

        $spf        = null;
        $dkim       = null;
        $dkimDomain = null;

        if (preg_match_all('/^Authentication-Results:\s*(.+)$/mi', $unfolded, $matches)) {
            foreach ($matches[1] as $value) {
                // Stop at ';' too — some MTAs write "spf=fail;" with no space before
                // the next method, and a bare \S+ would swallow the separator and
                // everything after it, so the result would never equal 'fail'/'pass'.
                if ($spf === null && preg_match('/\bspf\s*=\s*([^\s;]+)/i', $value, $m)) {
                    $spf = strtolower($m[1]);
                }
                if ($dkim === null && preg_match('/\bdkim\s*=\s*([^\s;]+)/i', $value, $m)) {
                    $dkim = strtolower($m[1]);
                    // The domain DKIM actually authenticated (RFC 8601's
                    // header.d= parameter, e.g. "dkim=pass header.d=gmail.com
                    // header.s=... header.b=...") — deliberately read only
                    // from the *same* Authentication-Results value as the
                    // dkim= verdict itself, not just "the first header.d=
                    // found anywhere", since a value can carry more than one
                    // method's own parameters. Used by
                    // BounceHandler::isDkimAuthenticated() to verify a
                    // bounce's DKIM signature genuinely belongs to the
                    // domain it's being trusted for, not just that *some*
                    // domain's signature happens to be present and valid.
                    if (preg_match('/header\.d\s*=\s*([^\s;]+)/i', $value, $dm)) {
                        $dkimDomain = strtolower(trim($dm[1]));
                    }
                }
            }
        }

        return ['spf' => $spf, 'dkim' => $dkim, 'dkimDomain' => $dkimDomain];
    }
}
