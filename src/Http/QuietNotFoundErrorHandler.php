<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http;

use Slim\Handlers\ErrorHandler;

/**
 * A 404 is already visible in nginx's own access log (request line + status,
 * see docker/nginx.conf's access_log) — logging the full exception on top of
 * that (type, message, file, line, stack trace) is pure noise, overwhelmingly
 * from bot/scanner probes for wp-content/PHP-shell paths that never touch
 * application logic. Registered only for HttpNotFoundException in
 * public/index.php; every other exception still goes through Slim's default
 * ErrorHandler and is logged in full.
 */
class QuietNotFoundErrorHandler extends ErrorHandler
{
    protected function writeToErrorLog(): void
    {
    }
}
