<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http;

use Slim\Handlers\ErrorHandler;

/**
 * A 404 is already visible in nginx's own access log (request line + status,
 * see docker/nginx.conf's access_log) — logging the full exception on top of
 * that (type, message, file, line, stack trace) is pure noise, overwhelmingly
 * from bot/scanner probes for wp-content/PHP-shell paths that never touch
 * application logic. A 405 from the same kind of probe is no different:
 * confirmed live, an automated `GET /.git/HEAD` scan happened to path-match
 * the `{listname}/{mail}` route (registered PUT/DELETE only) purely by
 * segment count, producing the exact same shape of noise. Registered for
 * both HttpNotFoundException and HttpMethodNotAllowedException in
 * public/index.php; every other exception still goes through Slim's default
 * ErrorHandler and is logged in full.
 */
class QuietBotNoiseErrorHandler extends ErrorHandler
{
    protected function writeToErrorLog(): void
    {
    }
}
