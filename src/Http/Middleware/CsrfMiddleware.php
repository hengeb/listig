<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Middleware;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;

class CsrfMiddleware implements MiddlewareInterface
{
    private const STATE_CHANGING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (!in_array($request->getMethod(), self::STATE_CHANGING_METHODS, true)) {
            return $handler->handle($request);
        }

        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $sessionId = session_id();
        $csrfToken = $request->getHeaderLine('X-CSRF-Token');

        if (empty($csrfToken) || !hash_equals($sessionId, $csrfToken)) {
            $response = new Response();
            $response->getBody()->write(json_encode(['error' => 'CSRF token invalid']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }

        return $handler->handle($request);
    }
}
