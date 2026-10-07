<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

/**
 * Organizational domain for DMARC relaxed alignment, without the Public Suffix
 * List (ADR-0018): the last two labels, or three when the last two form a
 * well-known multi-label public suffix (`co.uk`, `com.au`, shared hosting such
 * as `github.io`). A suffix missing from the table makes alignment too
 * generous for domains under it — which is why `sender-notices: authenticated`
 * additionally requires a *passing* verdict from the own MTA.
 */
class OrganizationalDomain
{
    private const array MULTI_LABEL_SUFFIXES = [
        // country-code second levels
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'ltd.uk', 'plc.uk', 'net.uk', 'sch.uk',
        'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'co.nz', 'org.nz', 'net.nz', 'ac.nz',
        'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'co.kr', 'or.kr', 'com.cn', 'net.cn', 'org.cn', 'gov.cn',
        'com.br', 'net.br', 'org.br', 'com.ar', 'com.mx', 'com.tr', 'com.pl', 'com.ua', 'com.sg',
        'com.hk', 'com.tw', 'com.my', 'com.vn', 'com.ph', 'co.id', 'co.in', 'net.in', 'org.in', 'ac.in',
        'co.il', 'co.za', 'org.za', 'co.at', 'or.at', 'gv.at', 'co.th', 'in.th',
        // shared hosting / user-content platforms
        'github.io', 'gitlab.io', 'blogspot.com', 'herokuapp.com', 'appspot.com', 'azurewebsites.net',
        'cloudfront.net', 'amazonaws.com', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev',
        'web.app', 'firebaseapp.com', 'wordpress.com', 'myshopify.com',
    ];

    public function of(string $domain): string
    {
        $domain = strtolower(trim($domain, " \t\n\r\0\x0B."));
        $labels = explode('.', $domain);
        $count = count($labels);
        if ($count <= 2) {
            return $domain;
        }
        $lastTwo = implode('.', array_slice($labels, -2));
        $take = in_array($lastTwo, self::MULTI_LABEL_SUFFIXES, true) ? 3 : 2;
        return implode('.', array_slice($labels, -$take));
    }

    /** Relaxed alignment: same organizational domain, both non-empty. */
    public function aligned(string $a, string $b): bool
    {
        $a = $this->of($a);
        return $a !== '' && $a === $this->of($b);
    }
}
