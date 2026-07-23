<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Like AuthMiddleware, but never redirects when no session exists — it just
 * exposes whichever user (or null) is present as the 'user' request attribute.
 *
 * Needed for the archive viewer routes: whether login is required at all depends
 * on the specific list's `archive` config (ArchiveMode::Public allows anonymous
 * access, Members/Owners don't), which isn't known until the controller has
 * resolved the list — a decision AuthMiddleware's blanket redirect-if-absent
 * can't express at the route-group level. ArchiveController reads
 * $request->getAttribute('user') exactly like ListController/DashboardController
 * do and applies the per-list access check itself.
 */
class OptionalAuthMiddleware implements MiddlewareInterface
{
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        return $handler->handle($request->withAttribute('user', $_SESSION['user'] ?? null));
    }
}
