<?php

declare(strict_types=1);

namespace Hengeb\Listig\Member;

class Member
{
    /**
     * The only fixed, guaranteed field is $email. Everything else a resolver
     * happens to know about a member (firstname, lastname, username, pronoun,
     * an LDAP employeeNumber, a custom "title" column/key, ...) lives in
     * $attributes, keyed by whatever name the backing store itself uses —
     * nothing beyond $email is hardcoded anywhere in this class or its
     * consumers. See MailProcessor::buildRecipientContext()/buildMailContext(),
     * which expose $attributes as variables directly under their own names.
     *
     * @param array<string, string> $attributes
     */
    public function __construct(
        public readonly string $email,
        public readonly array $attributes = [],
    ) {
    }
}
