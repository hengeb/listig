<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

final class FilterResult
{
    private function __construct(
        private readonly string $type,
        /** Translation key (see translations/messages.*.yaml), not a literal message. */
        public readonly string $reason = '',
        public readonly array $reasonParams = [],
    ) {
    }

    public static function discard(): self
    {
        return new self('discard');
    }

    public static function bounce(): self
    {
        return new self('bounce');
    }

    public static function reject(string $reason = '', array $reasonParams = []): self
    {
        return new self('reject', $reason, $reasonParams);
    }

    public static function moderation(): self
    {
        return new self('moderation');
    }

    public static function distribute(): self
    {
        return new self('distribute');
    }

    public bool $isDiscard {
        get => $this->type === 'discard';
    }

    public bool $isBounce {
        get => $this->type === 'bounce';
    }

    public bool $isReject {
        get => $this->type === 'reject';
    }

    public bool $isModeration {
        get => $this->type === 'moderation';
    }

    public bool $isDistribute {
        get => $this->type === 'distribute';
    }
}
