<?php

declare(strict_types=1);

namespace Hengeb\Listig\Variable;

/**
 * Resolves {key} placeholders in template strings.
 *
 * Contexts are arrays of key => value|callable pairs, merged via array_merge
 * so later entries override earlier ones. Each key should appear in at most
 * one context. A callable receives the current $contexts array and the active
 * ResolutionPurpose, and must return string|null.
 *
 * A key may be followed by a |filter:args pipeline, e.g.
 * {pronoun|match:he=>Lieber,she=>Liebe|default:Hallo} or {firstname|lowercase},
 * applied in order to the resolved value — see VariableFilter. Filters are not
 * part of key lookup/cycle-detection: those operate on the key alone. A
 * filter's args may themselves contain {} placeholders, resolved before the
 * filter runs — e.g. {list-mail|default:system@{domain|default:localhost}}.
 * Placeholder scanning is brace-depth aware (walkPlaceholders()/
 * findMatchingBrace()), not a plain [^}]+ regex, specifically so this nesting
 * works instead of being cut off at the first '}'.
 *
 * Every call is tagged with a ResolutionPurpose (default: Disclosed), threaded
 * unchanged through recursive resolution, same as $visited. If a key in
 * BLOCKED_KEYS (passwords, hostnames, etc.) is looked up under Disclosed, the
 * real value is never returned — CLASSIFIED_PLACEHOLDER is substituted instead
 * and the attempt is logged. Only ResolutionPurpose::Trusted bypasses this
 * (used solely by ListConfig::$imapHost/$imapUser/$imapPassword/$smtpHost/
 * $smtpUser/$smtpPassword, which must resolve these exact keys to build the
 * actual IMAP/SMTP connection).
 * This is enforced here, at the single point of {} resolution, rather than by
 * every caller remembering to hand over a pre-filtered context — which cannot
 * work at all for resolution that happens before a ListConfig exists yet (e.g.
 * a provider's own list-mail bootstrap resolution).
 *
 * A value is only recursively re-resolved as a template if it is a plain
 * string taken directly from a context array — i.e. fully operator-authored
 * config (a `vorname: "{firstname}"` alias, `list-mail: "{list-name}@..."`).
 * Three other kinds of value are always treated as terminal, even if they
 * contain '{':
 *   - Callables (e.g. MailProcessor's 'sender-name'), since their result can
 *     depend on the incoming mail's raw From: header, which an external
 *     sender controls.
 *   - Literal-wrapped values (see Literal), used for anything sourced from a
 *     Member record — firstname, a custom LDAP attribute, etc. Those ultimately
 *     come from a directory/database/CSV row or a self-service subscribe
 *     request, not list config, so a member setting their own "firstname" to
 *     literally "{someOtherAttribute}" must not be able to trigger a second
 *     lookup that a `personalize:` whitelist never approved for that key.
 *   - CLASSIFIED_PLACEHOLDER itself, for the same reason.
 * Without the first two exclusions, either a crafted `From: "{sender-someAttribute}" <x@y>`
 * or a self-chosen attribute value containing '{' could leak another
 * attribute's value into a mail, sidestepping the personalize: whitelist
 * entirely (the whitelist only gates the top-level placeholder, not what a
 * resolved value's own nested '{}' syntax would otherwise trigger).
 *
 * A key not found in any context resolves to an empty string (logged), not a
 * literal {key} left in the output — member attributes are fully dynamic (see
 * Member::$attributes), so "this recipient simply has no pronoun/title/whatever"
 * is an expected, per-recipient condition, not a config error; leaking raw
 * {key} syntax into a sent mail would be worse than a quiet blank. Genuine
 * config typos are still visible via the error_log, same as cycle detection.
 *
 * Usage:
 *   $result = VariableResolver::resolve($template, [$listContext, $mailContext], ResolutionPurpose::Disclosed);
 *   $value  = VariableResolver::lookup('list-name', $contexts); // raw lookup without template parsing
 */
class VariableResolver
{
    /**
     * Keys that must never be reachable through {} template resolution under
     * ResolutionPurpose::Disclosed — passwords, hostnames, and other infra
     * values that would leak a credential (or a fragment of one, e.g. via an
     * int-cast port number) into mail content or the UI if referenced there,
     * whether by an operator's config mistake or a crafted alias chain.
     */
    public const array BLOCKED_KEYS = [
        'password', 'mail-password', 'imap-password', 'smtp-password',
        'ldap-bind-password', 'db-password', 'api-token',
        'mail-user', 'imap-user', 'smtp-user',
        'mail-host', 'imap-host', 'imap-port', 'imap-secure',
        'smtp-host', 'smtp-port', 'smtp-secure',
        'db-host', 'db-port', 'db-name', 'db-user',
        'ldap-host', 'ldap-base-dn', 'ldap-bind-dn', 'ldap-list-dn',
        'oidc-provider-url', 'oidc-client-id', 'oidc-client-secret', 'oidc-public-provider-url',
        'oidc-logout-url',
    ];

    /** Substituted for a BLOCKED_KEYS value looked up under ResolutionPurpose::Disclosed. */
    public const string CLASSIFIED_PLACEHOLDER = '*CLASSIFIED*';

    public static function resolve(
        string $template,
        array $contexts,
        ResolutionPurpose $purpose = ResolutionPurpose::Disclosed,
        array $visited = [],
    ): string {
        return self::walkPlaceholders(
            $template,
            fn(string $inner): string => self::resolvePlaceholder($inner, $contexts, $purpose, $visited),
        );
    }

    /**
     * Walks $template and invokes $resolveInner for each top-level {...}
     * placeholder, passing its inner content (braces stripped). Brace-depth
     * aware, so a placeholder whose filter args themselves contain {} (e.g.
     * {list-mail|default:system@{domain|default:localhost}}) is handed to
     * $resolveInner whole, rather than being cut off at the first '}' the way
     * a plain [^}]+ regex would. Text outside placeholders is copied verbatim.
     * A '{' with no matching '}' is copied as a literal character — malformed
     * input, not a placeholder.
     */
    public static function walkPlaceholders(string $template, callable $resolveInner): string
    {
        if (!str_contains($template, '{')) {
            return $template;
        }

        $result = '';
        $i = 0;
        $len = strlen($template);
        while ($i < $len) {
            if ($template[$i] !== '{') {
                $result .= $template[$i];
                $i++;
                continue;
            }
            $end = self::findMatchingBrace($template, $i);
            if ($end === null) {
                $result .= '{';
                $i++;
                continue;
            }
            $result .= $resolveInner(substr($template, $i + 1, $end - $i - 1));
            $i = $end + 1;
        }
        return $result;
    }

    private static function resolvePlaceholder(string $inner, array $contexts, ResolutionPurpose $purpose, array $visited): string
    {
        [$key, $filters] = self::splitKeyAndFilters($inner);

        if (in_array($key, $visited, true)) {
            error_log("Listig: Variable cycle detected for key '$key'");
            return '{' . $inner . '}';
        }

        [$value, $recursable] = self::lookupWithSource($key, $contexts, $purpose);
        if ($value === null) {
            // Falls through to the filter pipeline below (e.g. |default:...)
            // instead of returning early — a member simply not having a given
            // attribute is exactly the case VariableFilter's 'default' filter
            // documents itself as handling (see its docblock), so an absent
            // key must still reach it, not bypass filters entirely.
            error_log("Listig: Variable '$key' not found, substituting empty string");
            $value = '';
        } elseif ($recursable && str_contains($value, '{')) {
            $value = self::resolve($value, $contexts, $purpose, [...$visited, $key]);
        }

        foreach ($filters as $filter) {
            // A filter's args may themselves contain {} placeholders (e.g.
            // "default:system@{domain|default:localhost}") — resolve those
            // first, so VariableFilter::apply() always sees plain text.
            $resolvedFilter = str_contains($filter, '{') ? self::resolve($filter, $contexts, $purpose, $visited) : $filter;
            $value = VariableFilter::apply($resolvedFilter, $value);
        }

        return $value;
    }

    /** The bare variable name of a {key|filter:...} placeholder, ignoring any filter pipeline. */
    public static function baseKey(string $raw): string
    {
        return explode('|', $raw, 2)[0];
    }

    /** @return array{0: string, 1: string[]} [$key, $filterSpecs] */
    private static function splitKeyAndFilters(string $raw): array
    {
        $parts = self::splitTopLevel($raw, '|');
        $key = array_shift($parts);
        return [$key, $parts];
    }

    /**
     * Splits $str on $delimiter, ignoring any occurrence nested inside a {}
     * span — used so a filter pipeline's own '|' separators aren't confused
     * with a '|' inside a nested placeholder's filter args.
     *
     * @return string[]
     */
    private static function splitTopLevel(string $str, string $delimiter): array
    {
        $parts = [];
        $current = '';
        $depth = 0;
        for ($i = 0, $len = strlen($str); $i < $len; $i++) {
            $ch = $str[$i];
            if ($ch === '{') {
                $depth++;
            } elseif ($ch === '}') {
                $depth--;
            }
            if ($ch === $delimiter && $depth <= 0) {
                $parts[] = $current;
                $current = '';
            } else {
                $current .= $ch;
            }
        }
        $parts[] = $current;
        return $parts;
    }

    /** Returns the index of the '}' matching the '{' at $openPos, or null if unbalanced. */
    private static function findMatchingBrace(string $s, int $openPos): ?int
    {
        $depth = 0;
        for ($i = $openPos, $len = strlen($s); $i < $len; $i++) {
            if ($s[$i] === '{') {
                $depth++;
            } elseif ($s[$i] === '}') {
                $depth--;
                if ($depth === 0) {
                    return $i;
                }
            }
        }
        return null;
    }

    /**
     * Looks up a single key without template parsing.
     * Useful inside callables that need to reference sibling context values.
     * Later contexts override earlier ones (same semantics as array_merge).
     */
    public static function lookup(string $key, array $contexts, ResolutionPurpose $purpose = ResolutionPurpose::Disclosed): ?string
    {
        return self::lookupWithSource($key, $contexts, $purpose)[0];
    }

    /**
     * @return array{0: ?string, 1: bool} [$value, $recursable] — $recursable is
     *         true only for a plain string value taken directly from a context
     *         array (see class docblock); false for a Literal, a callable, or
     *         the CLASSIFIED_PLACEHOLDER sentinel.
     */
    private static function lookupWithSource(string $key, array $contexts, ResolutionPurpose $purpose): array
    {
        if ($purpose === ResolutionPurpose::Disclosed && in_array($key, self::BLOCKED_KEYS, true)) {
            error_log("Listig: Blocked disclosure of protected key '$key' (resolved with Disclosed purpose)");
            return [self::CLASSIFIED_PLACEHOLDER, false];
        }

        $merged = array_merge(...$contexts);
        if (!array_key_exists($key, $merged)) {
            return [null, false];
        }
        $raw = $merged[$key];

        if ($raw instanceof Literal) {
            return [$raw->value, false];
        }
        if (is_callable($raw)) {
            $value = $raw($contexts, $purpose);
            return [$value !== null ? (string) $value : null, false];
        }
        return [$raw !== null ? (string) $raw : null, true];
    }
}
