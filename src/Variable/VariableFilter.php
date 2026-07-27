<?php

declare(strict_types=1);

namespace Hengeb\Listig\Variable;

/**
 * Applies a single |filter:args pipeline segment (see VariableResolver) to an
 * already-resolved variable value. New filters are added as a new match() arm —
 * deliberately not one class per filter, since each is a few lines.
 */
final class VariableFilter
{
    public static function apply(string $spec, string $value): string
    {
        [$name, $args] = str_contains($spec, ':') ? explode(':', $spec, 2) : [$spec, ''];

        return match ($name) {
            'lowercase' => mb_strtolower($value),
            'uppercase' => mb_strtoupper($value),
            'match' => self::match($value, $args),
            // default:Standardwert — passes $value through unchanged unless it's
            // empty (e.g. a member with no pronoun, or a match filter earlier in
            // the pipeline that didn't match), in which case $args is used as-is.
            'default' => $value !== '' ? $value : $args,
            default => self::unknown($name, $value),
        };
    }

    /**
     * match:he=>Lieber,she=>Liebe — exact, case-sensitive match of $value against
     * the left side of each pair. No match (including when $value is empty) ->
     * empty string, not the original $value — a match filter is expected to always
     * replace, not pass through. Chain with |default:... (applied after, on the
     * pipeline's already-resolved value — see VariableResolver) for a fallback,
     * e.g. {pronoun|match:he=>Lieber,she=>Liebe|default:Hallo} — match() itself has
     * no notion of a fallback value of its own.
     *
     * Commas and "=>" cannot appear literally inside a pattern or replacement —
     * not needed for short salutation-style words, so no escaping is implemented.
     */
    private static function match(string $value, string $args): string
    {
        $replacements = [];
        foreach (explode(',', $args) as $pair) {
            if (!str_contains($pair, '=>')) {
                continue;
            }
            [$from, $to] = array_map('trim', explode('=>', $pair, 2));
            $replacements[$from] = $to;
        }
        return $replacements[$value] ?? '';
    }

    private static function unknown(string $name, string $value): string
    {
        error_log("Listig: Unknown variable filter '$name'");
        return $value;
    }
}
