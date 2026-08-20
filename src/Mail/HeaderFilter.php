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
     * Every distinct connecting-client IP recorded across *all* Received:
     * headers in the given text — added by whichever mail server actually
     * observed each TCP hop, never something a message's own sender can
     * influence (same trust level as Return-Path, which this codebase
     * already relies on for the same reason) — each normalized via
     * normalizeIp(), in header order (topmost/most-recently-prepended
     * first). A Received header with no "from" clause at all
     * (`Received: by HOST (Postfix)` — a purely local injection, no network
     * hop) or one whose "from" clause carries no bracketed IP contributes
     * nothing and is silently skipped, not an error.
     *
     * Deliberately returns *every* hop, not just the topmost one: a single
     * combined send+receive mail server — Postfix handing a message to its
     * own mailbox via LMTP, the common self-hosted setup — always shows its
     * own IP on that final, innermost hop *regardless of whether the
     * message was genuinely generated locally or merely externally
     * SMTP-submitted and then delivered locally*. Confirmed live: a real
     * production bounce's topmost header was `Received: from
     * mail.example.org ([10.11.0.5]) by mail.example.org with LMTP ...` —
     * identical in shape to what an attacker's forged bounce, submitted via
     * SMTP to that same server, would also show at that same final hop. The
     * *next* header back — `Received: by mail.example.org (Postfix)`, no
     * "from" clause — is what actually proved this specific bounce was
     * injected locally by Postfix's own bounce daemon, never externally
     * SMTP-submitted at all; an attacker's forgery would instead show a real
     * external "from ATTACKER-HOST (... [ATTACKER-IP])" hop somewhere in the
     * chain, added by the receiving server itself and therefore impossible
     * to spoof away regardless of what the attacker's own submitted content
     * claims. Only walking every hop back this far can tell the two apart —
     * the topmost one alone cannot.
     *
     * Used by BounceHandler::isFromTrustedRelay() — see CLAUDE.md "Automatic
     * bounce actions" for why a live-SMTP-time rejection relayed back by the
     * operator's own outbound relay needs this instead of DKIM, which is
     * structurally unavailable for that bounce shape.
     *
     * @return string[]
     */
    public function readAllConnectingIps(string $headersRaw): array
    {
        $unfolded = $this->unfold($headersRaw);
        if (!preg_match_all('/^Received:\s*(.+)$/mi', $unfolded, $matches)) {
            return [];
        }

        $ips = [];
        foreach ($matches[1] as $value) {
            if (preg_match('/^from\b.*?\[([0-9A-Fa-f.:]+)\]/i', $value, $m)) {
                $ip = self::normalizeIp($m[1]);
                if ($ip !== null) {
                    $ips[] = $ip;
                }
            }
        }
        return $ips;
    }

    /**
     * Canonical form of an IP address (via an inet_pton/inet_ntop round trip,
     * e.g. collapsing IPv6 zero-run notation variants to one form) so two
     * different textual spellings of the same address still compare equal —
     * null for anything that isn't actually a valid IPv4/IPv6 address.
     */
    public static function normalizeIp(string $ip): ?string
    {
        $binary = @inet_pton(trim($ip));
        return $binary === false ? null : inet_ntop($binary);
    }

    /**
     * True if $ip (already normalized, see normalizeIp()) is a genuinely
     * public, routable address — false for RFC 1918 (10/8, 172.16/12,
     * 192.168/16)/RFC 4193 (IPv6 unique-local) private ranges and
     * loopback/link-local/other reserved ranges. Lets
     * BounceHandler::isFromTrustedRelay() auto-trust any hop that never left
     * the operator's own private network, with zero configuration needed
     * for the common case of a single, self-hosted mail server (or a small
     * private network of them) handling both outbound sending and inbound
     * delivery.
     */
    public static function isPublicIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
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
