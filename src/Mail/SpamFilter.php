<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use PhpImap\IncomingMail;

/**
 * Global (list-independent) content-based spam filter, configured via the
 * top-level `filters:` section of config.yml. Each rule matches one field
 * (subject/body/from/to) against either a literal substring (case-insensitive
 * str_contains) or, when the value is a /delimited/ pattern, a regular
 * expression (preg_match, case-sensitive unless the pattern's own flags say
 * otherwise) — same convention as most PCRE-based config formats.
 */
class SpamFilter
{
    private const FIELDS = ['subject', 'body', 'from', 'to'];
    private const DELIMITERS = ['/', '#', '~', '%', '!'];

    /** @var array<int, array<int, array{field: string, pattern: string, isRegex: bool}>> */
    private readonly array $rules;

    /** @param array<int, array<string, mixed>> $rawRules */
    public function __construct(array $rawRules)
    {
        $this->rules = array_map($this->normalizeRule(...), $rawRules);
    }

    /**
     * A mail matches (is spam) if any *rule* matches — but a rule with more than
     * one key (e.g. `to: foo` + `subject: bar` in the same list entry) only
     * matches when *all* of its conditions match (AND). Different top-level
     * entries in filters: remain OR'd against each other, unchanged.
     */
    public function matches(IncomingMail $mail): bool
    {
        foreach ($this->rules as $conditions) {
            if ($this->allConditionsMatch($conditions, $mail)) {
                return true;
            }
        }

        return false;
    }

    /** @param array<int, array{field: string, pattern: string, isRegex: bool}> $conditions */
    private function allConditionsMatch(array $conditions, IncomingMail $mail): bool
    {
        foreach ($conditions as $condition) {
            $value = $this->fieldValue($condition['field'], $mail);

            if ($condition['isRegex']) {
                if (@preg_match($condition['pattern'], $value) !== 1) {
                    return false;
                }
            } elseif (!str_contains(strtolower($value), $condition['pattern'])) {
                return false;
            }
        }

        return true;
    }

    private function fieldValue(string $field, IncomingMail $mail): string
    {
        return match ($field) {
            'subject' => $mail->subject ?? '',
            'body' => ($mail->textPlain ?? '') . "\n" . ($mail->textHtml ?? ''),
            'from' => ($mail->fromName ?? '') . ' ' . ($mail->fromAddress ?? ''),
            'to' => $mail->toString ?? '',
        };
    }

    /**
     * @param array<string, mixed> $rawRule One or more field => pattern pairs,
     *     ANDed together (see matches()) — a single-key entry is just the
     *     degenerate one-condition case.
     * @return array<int, array{field: string, pattern: string, isRegex: bool}>
     */
    private function normalizeRule(array $rawRule): array
    {
        if (count($rawRule) === 0) {
            throw new \RuntimeException('Each entry in filters: must have at least one key (subject/body/from/to)');
        }

        $conditions = [];
        foreach ($rawRule as $field => $pattern) {
            if (!in_array($field, self::FIELDS, true)) {
                throw new \RuntimeException(
                    "Unknown filters: field '$field' — expected one of: " . implode(', ', self::FIELDS)
                );
            }

            if (!is_string($pattern) || $pattern === '') {
                throw new \RuntimeException("filters: entry for '$field' must be a non-empty string");
            }

            $isRegex = $this->isRegex($pattern);
            if ($isRegex && @preg_match($pattern, '') === false) {
                throw new \RuntimeException("filters: invalid regular expression for '$field': $pattern");
            }

            // Literal patterns are matched case-insensitively — lowercase once here so
            // matches() only has to lowercase the (per-mail, per-check) field value.
            $conditions[] = ['field' => $field, 'pattern' => $isRegex ? $pattern : strtolower($pattern), 'isRegex' => $isRegex];
        }

        return $conditions;
    }

    private function isRegex(string $pattern): bool
    {
        if (strlen($pattern) < 2 || !in_array($pattern[0], self::DELIMITERS, true)) {
            return false;
        }

        $lastPos = strrpos($pattern, $pattern[0]);
        if ($lastPos === false || $lastPos === 0) {
            return false;
        }

        return preg_match('/^[a-zA-Z]*$/', substr($pattern, $lastPos + 1)) === 1;
    }
}
