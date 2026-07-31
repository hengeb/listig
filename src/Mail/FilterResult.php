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
        /**
         * Whether the mail should be deleted outright (ImapArchiver::delete()),
         * ignoring the list's own `archive:` setting entirely, rather than the
         * normal per-outcome IMAP handling — nothing for a bare discard() (the
         * X-Loop case, bin/worker.php step 1, deliberately leaves the mail sitting
         * in the inbox for manual inspection) or ImapArchiver::archiveOrDelete()
         * for reject()/bounce() (which archives or deletes depending on
         * `archive:`). Set true only for a `filters:` spam match (see
         * SpamFilter/IncomingMailFilter) — a spam-filtered mail sitting in the
         * archive folder forever serves no one, regardless of what the list
         * archives everything else as.
         */
        public readonly bool $forceDelete = false,
    ) {
    }

    public static function discard(bool $forceDelete = false): self
    {
        return new self('discard', forceDelete: $forceDelete);
    }

    public static function bounce(): self
    {
        return new self('bounce');
    }

    public static function reject(string $reason = '', array $reasonParams = [], bool $forceDelete = false): self
    {
        return new self('reject', $reason, $reasonParams, $forceDelete);
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
