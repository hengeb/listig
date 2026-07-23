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

    /** @var array<int, array{field: string, pattern: string, isRegex: bool}> */
    private readonly array $rules;

    /** @param array<int, array<string, mixed>> $rawRules */
    public function __construct(array $rawRules)
    {
        $this->rules = array_map($this->normalizeRule(...), $rawRules);
    }

    public function matches(IncomingMail $mail): bool
    {
        foreach ($this->rules as $rule) {
            $value = $this->fieldValue($rule['field'], $mail);

            if ($rule['isRegex']) {
                if (@preg_match($rule['pattern'], $value) === 1) {
                    return true;
                }
            } elseif (str_contains(strtolower($value), $rule['pattern'])) {
                return true;
            }
        }

        return false;
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
     * @param array<string, mixed> $rawRule
     * @return array{field: string, pattern: string, isRegex: bool}
     */
    private function normalizeRule(array $rawRule): array
    {
        if (count($rawRule) !== 1) {
            throw new \RuntimeException(
                'Each entry in filters: must have exactly one key (subject/body/from/to), got: ' . json_encode($rawRule)
            );
        }

        $field = array_key_first($rawRule);
        if (!in_array($field, self::FIELDS, true)) {
            throw new \RuntimeException(
                "Unknown filters: field '$field' — expected one of: " . implode(', ', self::FIELDS)
            );
        }

        $pattern = $rawRule[$field];
        if (!is_string($pattern) || $pattern === '') {
            throw new \RuntimeException("filters: entry for '$field' must be a non-empty string");
        }

        $isRegex = $this->isRegex($pattern);
        if ($isRegex && @preg_match($pattern, '') === false) {
            throw new \RuntimeException("filters: invalid regular expression for '$field': $pattern");
        }

        // Literal patterns are matched case-insensitively — lowercase once here so
        // matches() only has to lowercase the (per-mail, per-check) field value.
        return ['field' => $field, 'pattern' => $isRegex ? $pattern : strtolower($pattern), 'isRegex' => $isRegex];
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
