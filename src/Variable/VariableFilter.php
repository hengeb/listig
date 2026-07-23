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
            default => self::unknown($name, $value),
        };
    }

    /**
     * match:he=>Lieber,she=>Liebe,default=>Hallo — exact, case-sensitive match of
     * $value against the left side of each pair; "default" is not a value to match
     * but the fallback used when nothing else matches (including when $value is
     * empty). No default and no match -> empty string, not the original $value —
     * a match filter is expected to always replace, not pass through.
     *
     * Commas and "=>" cannot appear literally inside a pattern or replacement —
     * not needed for short salutation-style words, so no escaping is implemented.
     */
    private static function match(string $value, string $args): string
    {
        $replacements = [];
        $default = '';
        foreach (explode(',', $args) as $pair) {
            if (!str_contains($pair, '=>')) {
                continue;
            }
            [$from, $to] = array_map('trim', explode('=>', $pair, 2));
            if ($from === 'default') {
                $default = $to;
            } else {
                $replacements[$from] = $to;
            }
        }
        return $replacements[$value] ?? $default;
    }

    private static function unknown(string $name, string $value): string
    {
        error_log("Listig: Unknown variable filter '$name'");
        return $value;
    }
}
