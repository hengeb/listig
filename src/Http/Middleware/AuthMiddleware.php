<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

class AuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly bool $oidcEnabled = false,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $user = $_SESSION['user'] ?? null;

        if ($user === null) {
            $response = new Response();

            // A deep link (e.g. a bookmarked manage page) should skip the login
            // form entirely and go straight to the IdP when OIDC is the only
            // configured way in — AuthController::loginOidc() reads this same
            // 'next' param (stashed in the session across the round trip to the
            // IdP) and redirects back here once login succeeds, instead of
            // always landing on the dashboard. Without OIDC configured, the
            // magic-link flow has no equivalent "next" concept (see CLAUDE.md),
            // so the plain /_/login form is still the right target.
            if ($this->oidcEnabled) {
                $next = urlencode(self::relativeTarget($request));
                return $response->withHeader('Location', "/_/login/oidc?next={$next}")->withStatus(302);
            }

            return $response->withHeader('Location', '/_/login')->withStatus(302);
        }

        $request = $request->withAttribute('user', $user);

        return $handler->handle($request);
    }

    private static function relativeTarget(ServerRequestInterface $request): string
    {
        $uri = $request->getUri();
        $target = $uri->getPath();
        if ($uri->getQuery() !== '') {
            $target .= '?' . $uri->getQuery();
        }
        return $target;
    }
}
