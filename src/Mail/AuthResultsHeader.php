<?php

declare(strict_types=1);

namespace Hengeb\Listig\Mail;

/**
 * One parsed Authentication-Results header (RFC 8601): the authserv-id of the
 * server that wrote it and its method results. Pure value object, produced by
 * HeaderFilter::parseAuthResults().
 */
final class AuthResultsHeader
{
    /**
     * @param list<array{method: string, result: string, props: array<string, string>}> $results
     *     method/result lowercase; props keyed `ptype.property` (lowercase) with
     *     unquoted values as written
     */
    public function __construct(
        public readonly string $authservId,
        public readonly array $results,
    ) {
    }

    /** @return array{method: string, result: string, props: array<string, string>}|null */
    public function first(string $method): ?array
    {
        return $this->all($method)[0] ?? null;
    }

    /** @return list<array{method: string, result: string, props: array<string, string>}> */
    public function all(string $method): array
    {
        return array_values(array_filter($this->results, fn(array $r) => $r['method'] === $method));
    }

    /** @param string $value the (unfolded) header value after "Authentication-Results:" */
    public static function parse(string $value): ?self
    {
        $chunks = self::splitResinfo($value);
        $head = trim(array_shift($chunks) ?? '');
        // "authserv-id [version]" — the id is the first token.
        $authservId = strtolower(preg_split('/\s+/', $head)[0] ?? '');
        if ($authservId === '') {
            return null;
        }

        $results = [];
        foreach ($chunks as $chunk) {
            // method[/version]=result, then ptype.property=value pairs (values may be quoted).
            if (!preg_match_all('/([A-Za-z0-9_.\/-]+)\s*=\s*("(?:[^"\\\\]|\\\\.)*"|[^\s;]+)/', $chunk, $pairs, PREG_SET_ORDER)) {
                continue;
            }
            $first = array_shift($pairs);
            $method = strtolower(explode('/', $first[1])[0]);
            if (str_contains($method, '.')) {
                continue;
            }
            $props = [];
            foreach ($pairs as $pair) {
                $key = strtolower($pair[1]);
                if (str_contains($key, '.') && !isset($props[$key])) {
                    $props[$key] = self::unquote($pair[2]);
                }
            }
            $results[] = ['method' => $method, 'result' => strtolower(self::unquote($first[2])), 'props' => $props];
        }

        return new self($authservId, $results);
    }

    /**
     * Splits on ';' outside quoted strings and drops (nested) comments, so a
     * ';' or '=' inside a comment or quoted value can never fabricate a result.
     *
     * @return string[]
     */
    private static function splitResinfo(string $value): array
    {
        $chunks = [];
        $current = '';
        $depth = 0;
        $quoted = false;
        $len = strlen($value);
        for ($i = 0; $i < $len; $i++) {
            $c = $value[$i];
            if ($quoted) {
                $current .= $c;
                if ($c === '\\' && $i + 1 < $len) {
                    $current .= $value[++$i];
                } elseif ($c === '"') {
                    $quoted = false;
                }
            } elseif ($depth > 0) {
                if ($c === '\\') {
                    $i++;
                } elseif ($c === '(') {
                    $depth++;
                } elseif ($c === ')') {
                    $depth--;
                }
            } elseif ($c === '(') {
                $depth++;
                $current .= ' ';
            } elseif ($c === '"') {
                $quoted = true;
                $current .= $c;
            } elseif ($c === ';') {
                $chunks[] = $current;
                $current = '';
            } else {
                $current .= $c;
            }
        }
        $chunks[] = $current;
        return $chunks;
    }

    private static function unquote(string $v): string
    {
        if (strlen($v) >= 2 && $v[0] === '"' && str_ends_with($v, '"')) {
            return stripslashes(substr($v, 1, -1));
        }
        return $v;
    }
}
