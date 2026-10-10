<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Shared helpers for the '?next=' deep-link redirect target: wherever an unauthenticated
 * visitor is sent to a login page (/_/login/oidc or the /_/login form) — AuthMiddleware
 * (protected pages) and ArchiveController (login-gated archive views) — the login page gets
 * the exact same "current path + query string" and sends the visitor back there afterwards;
 * AuthController validates it with sanitizeNext(). See docs/architecture/web-ui.md
 * "Deep-link redirect-back".
 */
final class RequestPath
{
    public static function relativeTarget(ServerRequestInterface $request): string
    {
        $uri = $request->getUri();
        $target = $uri->getPath();
        if ($uri->getQuery() !== '') {
            $target .= '?' . $uri->getQuery();
        }
        return $target;
    }

    /** `$loginPath` (e.g. "/_/login") with the current request as its `?next=` target. */
    public static function withNext(string $loginPath, ServerRequestInterface $request): string
    {
        return $loginPath . '?next=' . urlencode(self::relativeTarget($request));
    }

    /**
     * Only a same-origin relative path is ever accepted as a post-login redirect target — 'next'
     * ultimately originates from a query string an attacker fully controls (a crafted deep link
     * pointing at this app), so anything that could make the browser leave this origin is rejected
     * outright rather than trusted: a full URL, or a scheme-relative "//evil.example" (browsers
     * resolve that as https://evil.example, not a path). Capped at 512 characters, since it also
     * travels inside the magic-link token.
     */
    public static function sanitizeNext(mixed $next): ?string
    {
        if (!is_string($next) || $next === '' || strlen($next) > 512) {
            return null;
        }
        if (!str_starts_with($next, '/') || str_starts_with($next, '//') || str_starts_with($next, '/\\')) {
            return null;
        }
        if (parse_url($next, PHP_URL_SCHEME) !== null || parse_url($next, PHP_URL_HOST) !== null) {
            return null;
        }
        if (preg_match('/[\x00-\x1f\x7f]/', $next)) {
            return null; // control characters (header injection, CR/LF)
        }
        return $next;
    }
}
