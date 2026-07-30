<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Shared helper for building the '?next=' deep-link redirect target used
 * wherever an unauthenticated visitor gets sent straight to /_/login/oidc
 * instead of the login form — AuthMiddleware (protected pages) and
 * ArchiveController (login-gated archive views) both need the exact same
 * "current path + query string" value, see CLAUDE.md "Deep-link redirect-back".
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
}
