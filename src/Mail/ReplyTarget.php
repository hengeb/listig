<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Member\Member;

/** The resolved recipient behind a `+r-{TOKEN}` address — see ReplyTargetStore::resolveFromMail(). */
final readonly class ReplyTarget
{
    public function __construct(
        /** For a member: their *current* address, not the one stored when the token was issued. */
        public Member $recipient,
        public bool $external,
    ) {
    }
}
