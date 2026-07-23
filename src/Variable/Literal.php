<?php

declare(strict_types=1);

namespace Hengeb\Listig\Variable;

/**
 * Wraps a context value to mark it terminal: VariableResolver::resolve() never
 * recurses into it, even if it contains '{'. Used for anything sourced from a
 * Member record (or the incoming mail's recipient address) — data an external
 * sender or self-service subscriber ultimately controls, as opposed to a
 * plain string context value, which is always operator-authored config (e.g.
 * a `vorname: "{firstname}"` alias) and safe to treat as a further template.
 */
final class Literal
{
    public function __construct(public readonly string $value)
    {
    }
}
