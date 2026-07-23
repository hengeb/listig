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
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $user = $_SESSION['user'] ?? null;

        if ($user === null) {
            $response = new Response();
            return $response->withHeader('Location', '/_/login')->withStatus(302);
        }

        $request = $request->withAttribute('user', $user);

        return $handler->handle($request);
    }
}
