<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

/** Outcome of SenderNoticePolicy::decide(). */
final class NoticeDecision
{
    private function __construct(
        public readonly bool $send,
        public readonly bool $attachOriginal,
        /** Why nothing is sent (log token); null when sending. */
        public readonly ?string $suppressReason,
    ) {
    }

    public static function send(bool $attachOriginal): self
    {
        return new self(true, $attachOriginal, null);
    }

    public static function suppress(string $reason): self
    {
        return new self(false, false, $reason);
    }
}
