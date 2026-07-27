<?php

declare(strict_types=1);

use Hengeb\Listig\Config\ConfigResolver;
use Hengeb\Listig\Http\Controller\ArchiveController;
use Hengeb\Listig\Http\Controller\AuthController;
use Hengeb\Listig\Http\Controller\DashboardController;
use Hengeb\Listig\Http\Controller\ListApiController;
use Hengeb\Listig\Http\Controller\ListController;
use Hengeb\Listig\Http\Controller\ModerationController;
use Hengeb\Listig\Http\Controller\QueueController;
use Hengeb\Listig\Http\Controller\UnsubscribeController;
use Hengeb\Listig\Http\Middleware\ApiTokenMiddleware;
use Hengeb\Listig\Http\Middleware\AuthMiddleware;
use Hengeb\Listig\Http\Middleware\CsrfMiddleware;
use Hengeb\Listig\Http\Middleware\OptionalAuthMiddleware;
use Slim\Factory\AppFactory;
use Slim\Routing\RouteCollectorProxy;
use Symfony\Component\Ldap\Ldap;

require_once __DIR__ . '/../vendor/autoload.php';

// Load .env if it exists
$envFile = __DIR__ . '/../.env';
if (file_exists($envFile)) {
    foreach (file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        if (str_starts_with($line, '#') || !str_contains($line, '=')) {
            continue;
        }
        [$key, $value] = explode('=', $line, 2);
        $_ENV[trim($key)] = trim($value);
        putenv(trim($key) . '=' . trim($value));
    }
}

$container = require __DIR__ . '/../config/container.php';

AppFactory::setContainer($container);
$app = AppFactory::create();

$app->addErrorMiddleware(true, true, true);
$app->addBodyParsingMiddleware();

// Public routes. Anything not scoped to a specific list lives under the reserved
// '/_/' prefix — list routes are a single bare path segment ('/{listname}', see
// below), so a static, >=2-segment prefix like '/_/...' can never collide with one
// regardless of route registration order (see ListConfig::RESERVED_NAME, which
// forbids a list literally named '_').
$app->get('/_/login', [AuthController::class, 'showLogin']);
$app->post('/_/login', [AuthController::class, 'sendMagicLink']);
$app->get('/_/login/verify', [AuthController::class, 'verifyToken']);

// OIDC login — see "Authentication (OIDC)" in CLAUDE.md. Registered only when
// configured (same 404-if-unconfigured philosophy as the List Management API's
// api-token gate) — both the login-initiation *and* callback (its own redirect_uri)
// leg of the flow share this one route, distinguished by AuthController::loginOidc()
// via the presence of ?code/?error, matching the reference this was modeled on.
//
// This is also the earliest point in the request that touches the container —
// 'oidc.enabled' needs ConfigResolver, whose constructor eagerly parses and
// $VAR-substitutes the *entire* config.yml (every block, provider, and filter,
// not just OIDC-related keys, see ConfigResolver::__construct()), so a config
// error anywhere (an unset $VAR, invalid YAML, a bad `filters:` regex, ...)
// surfaces right here, for every single request, regardless of which list or
// feature is actually broken. Uncaught, that's a raw fatal error outside Slim's
// own request pipeline entirely (addErrorMiddleware only wraps $app->run(),
// which hasn't started yet) — catch it here instead and fail the same way
// public/index.php's own /_/health route already does for a broken LDAP config:
// logged clearly, degrading to a clean response rather than a stack trace on
// stderr with nothing sent to the client.
try {
    if ($container->get('oidc.enabled')) {
        $app->get('/_/login/oidc', [AuthController::class, 'loginOidc']);
    }
} catch (\Throwable $e) {
    error_log('Listig: FATAL: could not handle request, config.yml is invalid: ' . $e->getMessage());
    http_response_code(500);
    exit;
}

$app->get('/{listname}/unsubscribe', [UnsubscribeController::class, 'unsubscribe']);

// List-management API: Bearer-token auth, scoped per list via ApiTokenMiddleware
// (see CLAUDE.md "List Management API"). Not part of the session/CSRF-protected
// group below — this is a separate, machine-to-machine auth model.
$app->put('/{listname}/{mail}', [ListApiController::class, 'subscribe'])
    ->add(ApiTokenMiddleware::class);
$app->delete('/{listname}/{mail}', [ListApiController::class, 'unsubscribe'])
    ->add(ApiTokenMiddleware::class);
$app->post('/{listname}/encrypt-password', [ListApiController::class, 'encryptPassword'])
    ->add(ApiTokenMiddleware::class);

// Double opt-in subscribe: requestSubscribe does its own Bearer-or-public-subscribe
// check (see ListApiController), so it is NOT behind ApiTokenMiddleware. confirmSubscribe
// is public — the token in the link is the only credential.
$app->post('/{listname}/subscribe', [ListApiController::class, 'requestSubscribe']);
$app->get('/{listname}/subscribe/confirm', [ListApiController::class, 'confirmSubscribe']);

// Archive viewer: whether login is required at all depends on the specific list's
// `archive` config (ArchiveMode::Public allows anonymous access, Members/Owners
// don't) — a per-list decision AuthMiddleware's blanket redirect-if-absent can't
// express at the route-group level. OptionalAuthMiddleware exposes the session
// user (or null) without forcing a redirect; ArchiveController applies the actual
// per-list access check itself (see CLAUDE.md "Archive access levels").
$app->group('', function (RouteCollectorProxy $group): void {
    $group->get('/{listname}/archive', [ArchiveController::class, 'index']);
    $group->get('/{listname}/archive/{id}', [ArchiveController::class, 'show']);
    $group->get('/{listname}/archive/{id}/frame', [ArchiveController::class, 'frame']);
    $group->get('/{listname}/archive/{id}/attachment/{index}', [ArchiveController::class, 'attachment']);
})->add(new OptionalAuthMiddleware());

/**
 * Attempts a bind for every distinct LDAP server referenced anywhere in
 * config.yml — both `type: ldap` list-providers and a `member-resolver:
 * {type: ldap, ...}` sub-config nested under `type: inline`/`database`/`yaml`
 * providers (see CLAUDE.md "member-resolver can be configured as a
 * sub-object"). Returns true if there is nothing to check (no LDAP configured
 * at all) or every configured server binds successfully.
 */
function checkLdapReachability(ConfigResolver $configResolver): bool
{
    $servers = [];
    foreach ($configResolver->getListProviderConfigs() as $config) {
        foreach ([$config, $config['member-resolver'] ?? []] as $ldapConfig) {
            if (($ldapConfig['type'] ?? null) !== 'ldap') {
                continue;
            }
            $key = $ldapConfig['ldap-host'] . '|' . $ldapConfig['ldap-bind-dn'];
            $servers[$key] = $ldapConfig;
        }
    }

    foreach ($servers as $ldapConfig) {
        $ldap = Ldap::create('ext_ldap', ['connection_string' => $ldapConfig['ldap-host']]);
        $ldap->bind($ldapConfig['ldap-bind-dn'], $ldapConfig['ldap-bind-password']);
    }

    return true;
}

// Health check
$app->get('/_/health', function ($request, $response) use ($container): \Psr\Http\Message\ResponseInterface {
    $status = ['db' => 'error', 'ldap' => 'error'];
    $httpStatus = 200;

    try {
        $db = $container->get(PDO::class);
        $db->query('SELECT 1');
        $status['db'] = 'ok';
    } catch (\Throwable) {
        $httpStatus = 503;
    }

    try {
        checkLdapReachability($container->get(ConfigResolver::class));
        $status['ldap'] = 'ok';
    } catch (\Throwable $e) {
        error_log('Listig: LDAP health check failed: ' . $e->getMessage());
        $httpStatus = 503;
    }

    $response->getBody()->write(json_encode($status));
    return $response->withStatus($httpStatus)->withHeader('Content-Type', 'application/json');
});

// Authenticated routes
$app->group('', function (RouteCollectorProxy $group): void {
    $group->get('/', [DashboardController::class, 'index']);
    $group->get('/{listname}', [ListController::class, 'manage']);

    // API routes (also need CSRF)
    $group->group('/_/api', function (RouteCollectorProxy $api): void {
        $api->post('/logout', [AuthController::class, 'logout']);
        $api->post('/moderation/{id}/accept', [ModerationController::class, 'accept']);
        $api->post('/moderation/{id}/reject', [ModerationController::class, 'reject']);
        $api->get('/queue/{listname}', [QueueController::class, 'status']);
        $api->delete('/queue/{id}', [QueueController::class, 'delete']);
        $api->post('/queue/{id}/retry', [QueueController::class, 'retry']);
    })->add(new CsrfMiddleware());
})->add(new AuthMiddleware());

$app->run();
