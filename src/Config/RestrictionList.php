<?php

declare(strict_types=1);

namespace Hengeb\Listig\Config;

/**
 * Global, list-independent sender restrictions from the top-level
 * `restricted-members:` section — see CLAUDE.md "Sperren (restricted-members:)".
 * A single mechanism for both a temporary, single-list write-only mute and a
 * permanent, instance-wide send-and-receive ban: each entry independently
 * chooses its scope (`lists:`/`except:`, omitted = every list) and whether it
 * also blocks receiving (`receive: false`, default true — send is always
 * restricted for a matching entry, receive is opt-in on top of that).
 */
final class RestrictionList
{
    /** @var array<array{mail: string, until: ?\DateTimeImmutable, receive: bool, lists: ?string[], except: ?string[]}> */
    private readonly array $entries;

    /** @param array<int, array<string, mixed>> $rawEntries */
    public function __construct(array $rawEntries)
    {
        $this->entries = array_map(fn(array $e) => [
            'mail' => $e['mail'],
            'until' => isset($e['until']) ? new \DateTimeImmutable((string) $e['until']) : null,
            'receive' => (bool) ($e['receive'] ?? true),
            'lists' => isset($e['lists']) ? (array) $e['lists'] : null,
            'except' => isset($e['except']) ? (array) $e['except'] : null,
        ], $rawEntries);
    }

    /** True if $email may not post to $listName — every matching entry restricts sending, unconditionally. */
    public function isSendRestricted(string $listName, string $email): bool
    {
        return $this->matches($listName, $email, requireReceive: false);
    }

    /** True if $email may not receive mail distributed by $listName — only entries with `receive: false`. */
    public function isReceiveRestricted(string $listName, string $email): bool
    {
        return $this->matches($listName, $email, requireReceive: true);
    }

    private function matches(string $listName, string $email, bool $requireReceive): bool
    {
        $email = strtolower($email);
        $now = new \DateTimeImmutable();

        foreach ($this->entries as $entry) {
            if (strtolower($entry['mail']) !== $email) {
                continue;
            }
            if ($entry['until'] !== null && $entry['until'] <= $now) {
                continue;
            }
            if ($entry['lists'] !== null && !in_array($listName, $entry['lists'], true)) {
                continue;
            }
            // Deliberately not gated on `lists:` being absent — except: simply
            // wins if a list happens to appear in both, no separate validation.
            if ($entry['except'] !== null && in_array($listName, $entry['except'], true)) {
                continue;
            }
            if ($requireReceive && $entry['receive']) {
                continue;
            }
            return true;
        }

        return false;
    }
}
