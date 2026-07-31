<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Logging\Logger;
use Hengeb\Listig\Variable\VariableResolver;
use PhpImap\IncomingMail;

/**
 * Global (list-independent-ly *configured*) content-based spam filter, from the
 * top-level `filters:` section of config.yml. Each rule matches one field
 * (subject/body/from/to) against either a literal substring (case-insensitive
 * str_contains) or, when the value is a /delimited/ pattern, a regular
 * expression (preg_match, case-sensitive unless the pattern's own flags say
 * otherwise) — same convention as most PCRE-based config formats.
 *
 * A pattern may itself contain `{}` variables (e.g. `from: "MAILER-DAEMON@{domain}"`)
 * — these are only resolvable per list (a domain/list-mail is a property of the
 * specific list a mail is being checked against, not of the global, list-independent
 * filter config), so unlike everything else here, they are deliberately NOT resolved
 * once at construction time. match() takes the current ListConfig and resolves each
 * condition's raw pattern against $list->createContext() fresh, per call — see
 * allConditionsMatch(). Case-folding (for a literal pattern) therefore also has to
 * happen post-resolution, at match time, not in normalizeRule() as before.
 */
class SpamFilter
{
    private const FIELDS = ['subject', 'body', 'from', 'to'];
    private const ACTIONS = ['reject', 'discard'];
    private const DELIMITERS = ['/', '#', '~', '%', '!'];

    /** @var array<int, array{conditions: array<int, array{field: string, pattern: string, isRegex: bool}>, action: string}> */
    private readonly array $rules;

    /** @param array<int, array<string, mixed>> $rawRules */
    public function __construct(
        array $rawRules,
        private readonly Logger $logger,
    ) {
        $this->rules = array_map($this->normalizeRule(...), $rawRules);
    }

    /**
     * A mail matches (is spam) if any *rule* matches — but a rule with more than
     * one field key (e.g. `to: foo` + `subject: bar` in the same list entry)
     * only matches when *all* of its conditions match (AND); `action:` is not a
     * condition, see normalizeRule(). Different top-level entries in filters:
     * remain OR'd against each other, unchanged.
     *
     * @return string|null the matching rule's action ('reject'/'discard'), or
     *     null if no rule matched at all
     */
    public function match(IncomingMail $mail, ListConfig $list): ?string
    {
        foreach ($this->rules as $index => $rule) {
            $matchedConditions = $this->matchConditions($rule['conditions'], $mail, $list);
            if ($matchedConditions === null) {
                continue;
            }

            // filters: rules are numbered 1-based here (not the array index) since
            // that's how an operator counting entries in their own filters.yml
            // would refer to "the third rule" — and the resolved pattern each
            // condition actually matched against is logged too (not just the raw,
            // possibly-{}-templated one from config.yml), since that's normally the
            // more useful piece for figuring out *why* a rule matched a given mail.
            $this->logger->debug(
                sprintf(
                    'Listig: filters: rule #%d matched (action: %s) — %s',
                    $index + 1,
                    $rule['action'],
                    implode(', ', $matchedConditions),
                ),
                $list->logLevel,
            );

            return $rule['action'];
        }

        return null;
    }

    /**
     * @param array<int, array{field: string, pattern: string, isRegex: bool}> $conditions
     * @return array<int, string>|null one "field: \"resolved pattern\"" description
     *     per condition if every condition matched (for match()'s debug log), or
     *     null the moment any condition fails to match.
     */
    private function matchConditions(array $conditions, IncomingMail $mail, ListConfig $list): ?array
    {
        // Built lazily, only once per rule, and only if at least one condition's
        // raw pattern actually contains a placeholder — most filters: entries
        // have none, so this avoids the (small but pointless) cost of building a
        // list context for a rule that never needs one.
        $context = null;
        $descriptions = [];

        foreach ($conditions as $condition) {
            $value = $this->fieldValue($condition['field'], $mail);

            $pattern = $condition['pattern'];
            if (str_contains($pattern, '{')) {
                $context ??= $list->createContext();
                $pattern = VariableResolver::resolve($pattern, [$context]);
            }

            if ($condition['isRegex']) {
                if (@preg_match($pattern, $value) !== 1) {
                    return null;
                }
            } elseif (!str_contains(strtolower($value), strtolower($pattern))) {
                return null;
            }

            $descriptions[] = "{$condition['field']}: \"{$pattern}\"";
        }

        return $descriptions;
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
     * @param array<string, mixed> $rawRule One or more field => pattern pairs
     *     (subject/body/from/to), ANDed together (see match()) — a single-key
     *     entry is just the degenerate one-condition case. `action` is a
     *     rule-level directive, not a match condition, and may appear alongside
     *     any number of field keys.
     * @return array{conditions: array<int, array{field: string, pattern: string, isRegex: bool}>, action: string}
     */
    private function normalizeRule(array $rawRule): array
    {
        if (count($rawRule) === 0) {
            throw new \RuntimeException('Each entry in filters: must have at least one key (subject/body/from/to)');
        }

        // Default 'reject' — the pre-existing behavior, still the common case: notify
        // the sender and go through the normal reject pipeline (see reject.spam).
        // 'discard' silently drops the mail instead — marked seen and removed from
        // the inbox the same way a normal reject is (archived or deleted, per the
        // list's own archive: setting — see ImapArchiver::archiveOrDelete(), which
        // is why this isn't called 'delete': it may not delete anything at all),
        // just with no notice to the sender (e.g. for mail that's confidently spam,
        // where a rejection notice would itself be unwanted noise, or could
        // backscatter to a forged sender address).
        $action = $rawRule['action'] ?? 'reject';
        if (!is_string($action) || !in_array($action, self::ACTIONS, true)) {
            throw new \RuntimeException(
                "filters: 'action' must be one of: " . implode(', ', self::ACTIONS) . ' (got: ' . json_encode($action) . ')'
            );
        }
        unset($rawRule['action']);

        if (count($rawRule) === 0) {
            throw new \RuntimeException('Each entry in filters: must have at least one field key (subject/body/from/to) besides action');
        }

        $conditions = [];
        foreach ($rawRule as $field => $pattern) {
            if (!in_array($field, self::FIELDS, true)) {
                throw new \RuntimeException(
                    "Unknown filters: field '$field' — expected one of: " . implode(', ', self::FIELDS) . ', action'
                );
            }

            if (!is_string($pattern) || $pattern === '') {
                throw new \RuntimeException("filters: entry for '$field' must be a non-empty string");
            }

            $isRegex = $this->isRegex($pattern);
            // Validated on the raw (possibly still-{}-templated) pattern — a `{}`
            // placeholder is always valid, inert PCRE syntax on its own (curly
            // braces that don't form a quantifier like {2,4} are literal), so this
            // still catches a genuinely broken delimiter/flag combination at
            // startup without needing a list in scope to resolve against first.
            if ($isRegex && @preg_match($pattern, '') === false) {
                throw new \RuntimeException("filters: invalid regular expression for '$field': $pattern");
            }

            // Case-folding a literal pattern happens later, in allConditionsMatch()
            // — not here — since a pattern containing a {} variable isn't fully
            // resolved yet at this point (see this class's own docblock).
            $conditions[] = ['field' => $field, 'pattern' => $pattern, 'isRegex' => $isRegex];
        }

        return ['conditions' => $conditions, 'action' => $action];
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
