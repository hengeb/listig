<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

/**
 * Builds the placeholder address a `mark-invalid` bounce action replaces a
 * member's own address with — see CLAUDE.md "Automatic bounce actions". The
 * single shared implementation of this format, used identically by
 * LdapMemberResolver/DatabaseMemberResolver/CsvMemberResolver so the three
 * backends can never drift apart on it.
 *
 * Deliberately appended *after* the original address rather than replacing
 * it — the result is self-documenting (an operator browsing the directory/
 * table can still see which real address this was and why/when it was
 * invalidated) without being a deliverable address any more, reusing the
 * `.invalid` (RFC 2606) placeholder-domain convention already used elsewhere
 * in this codebase (`noreply@{domain}.invalid`, the cid: rewrite fallback).
 */
final class InvalidatedEmail
{
    public static function build(string $email, string $reasonCode): string
    {
        $date = (new \DateTimeImmutable())->format('Y-m-d');
        return "{$email}.BOUNCE_{$reasonCode}.{$date}.invalid";
    }
}
