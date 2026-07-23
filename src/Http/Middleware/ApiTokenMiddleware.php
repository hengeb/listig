<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Middleware;

use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\RateLimit\RateLimiter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Slim\Routing\RouteContext;

/**
 * Guards the Bearer-token list-management API (PUT/DELETE subscribe, encrypt-password).
 * The token is list-scoped, configured as the plaintext `api-token` config key (same
 * merge chain as any other list config value) — deliberately not hashed, since the
 * client side must know the plaintext value anyway and may read it from the same
 * LDAP/DB configuration. A list with no `api-token` configured has this API disabled
 * entirely (404, as if the route didn't exist).
 *
 * On success, attaches the resolved ListConfig as the 'list' request attribute so
 * controllers don't need to re-fetch it.
 */
class ApiTokenMiddleware implements MiddlewareInterface
{
    /** Failed attempts per list within RateLimiter's fixed 10-minute window before responding 429. */
    private const MAX_FAILED_ATTEMPTS = 20;

    public function __construct(
        private readonly ListProvider $listProvider,
        private readonly RateLimiter $rateLimiter,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $route = RouteContext::fromRequest($request)->getRoute();
        $listName = $route?->getArgument('listname') ?? '';

        $list = $this->listProvider->getList($listName);
        if ($list === null || $list->apiToken === '') {
            return $this->json(['error' => 'Not found'], 404);
        }

        $authHeader = $request->getHeaderLine('Authorization');
        $providedToken = str_starts_with($authHeader, 'Bearer ') ? substr($authHeader, 7) : '';

        if ($providedToken === '' || !hash_equals($list->apiToken, $providedToken)) {
            error_log("Listig: invalid API token attempt for list '{$listName}'");
            if ($this->rateLimiter->isExceeded($listName, '__api-token__', self::MAX_FAILED_ATTEMPTS)) {
                return $this->json(['error' => 'Too many attempts'], 429);
            }
            return $this->json(['error' => 'Unauthorized'], 401);
        }

        return $handler->handle($request->withAttribute('list', $list));
    }

    private function json(array $data, int $status): ResponseInterface
    {
        $response = new Response();
        $response->getBody()->write(json_encode($data));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
