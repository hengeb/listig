<?php

declare(strict_types=1);

namespace Hengeb\Listig\Queue;

use Symfony\Component\Mime\Email;

/**
 * A queued mail is stored as two pieces (ADR-0023): the message **headers**, which differ per
 * recipient (the `List-Unsubscribe` token, a personalized `Subject`, ...) and are stored with each
 * `mail_queue` row, and the **body** — the top-level part's own headers plus all the content — which
 * is usually identical for every recipient and is stored once in `mail_bodies`, keyed by bodyKey().
 * `headers . body` is exactly what `Email::toString()` returns. Pure; no I/O.
 */
final class QueueMime
{
    /**
     * @return array{0: string, 1: string} [message headers incl. their terminating line break, body part incl. its own headers]
     */
    public static function split(Email $email): array
    {
        return [$email->getPreparedHeaders()->toString(), $email->getBody()->toString()];
    }

    /**
     * Content address of a body. Every multipart part picks a random boundary when it is serialized,
     * so two bodies that are the same mail would otherwise never match; the boundaries are replaced by
     * numbered placeholders (in order of appearance) before hashing. The stored body keeps its real
     * boundaries, which are consistent within itself, and the headers carry none of them.
     */
    public static function bodyKey(string $body): string
    {
        $boundaries = [];
        if (preg_match_all('/boundary=(?:"([^"]+)"|([^\s;"]+))/i', $body, $matches, PREG_SET_ORDER)) {
            foreach ($matches as $m) {
                $boundary = $m[2] ?? $m[1]; // group 2 only exists for the unquoted form
                if (!in_array($boundary, $boundaries, true)) {
                    $boundaries[] = $boundary;
                }
            }
        }
        // Longest first, so a boundary that is a prefix of another cannot corrupt it.
        $order = $boundaries;
        usort($order, fn(string $a, string $b) => strlen($b) <=> strlen($a));
        $replacements = [];
        foreach ($order as $boundary) {
            $replacements[$boundary] = 'LISTIG-BOUNDARY-' . (array_search($boundary, $boundaries, true) + 1);
        }

        return hash('sha256', strtr($body, $replacements));
    }
}
