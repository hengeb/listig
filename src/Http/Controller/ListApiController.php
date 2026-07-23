<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Crypto\PasswordCrypto;
use Hengeb\Listig\Mail\NotificationMailer;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\RateLimit\RateLimiter;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Bearer-token list-management API (see CLAUDE.md "List Management API"):
 *   PUT    /{listname}/{mail}             immediate subscribe
 *   DELETE /{listname}/{mail}              unsubscribe
 *   POST   /{listname}/subscribe           request double opt-in (Bearer or public-subscribe)
 *   GET    /{listname}/subscribe/confirm    confirm double opt-in (token in link)
 *   POST   /{listname}/encrypt-password    encrypt + persist a password
 *
 * PUT/DELETE/encrypt-password sit behind ApiTokenMiddleware, which already
 * resolved and attached the list as the 'list' request attribute.
 * requestSubscribe() has its own, more permissive check (see there).
 */
class ListApiController
{
    private const SUBSCRIBE_TOKEN_MAX_AGE = 48 * 3600;
    private const MAX_SUBSCRIBE_REQUESTS_PER_10MIN = 5;

    public function __construct(
        private readonly Engine $latte,
        private readonly TokenService $tokenService,
        private readonly ListProvider $listProvider,
        private readonly NotificationMailer $notificationMailer,
        private readonly RateLimiter $rateLimiter,
        private readonly PasswordCrypto $passwordCrypto,
        private readonly TranslatorInterface $translator,
        private readonly string $host,
    ) {
    }

    public function subscribe(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        /** @var ListConfig $list */
        $list = $request->getAttribute('list');
        $mail = strtolower(trim((string) $args['mail']));

        if (!filter_var($mail, FILTER_VALIDATE_EMAIL)) {
            return $this->json($response, ['error' => 'Invalid mail address'], 400);
        }

        $body = $request->getParsedBody() ?? [];
        $member = new Member($mail, $this->attributesFromBody($body));

        try {
            $list->addMember($member);
        } catch (\RuntimeException $e) {
            return $this->json($response, ['error' => $e->getMessage()], 409);
        }

        return $response->withStatus(204);
    }

    public function unsubscribe(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        /** @var ListConfig $list */
        $list = $request->getAttribute('list');
        $mail = strtolower(trim((string) $args['mail']));

        $list->removeMember($mail);

        return $response->withStatus(204);
    }

    /**
     * Reachable two ways, deliberately not gated by the strict ApiTokenMiddleware:
     * with a valid Bearer token (always allowed, e.g. a trusted server-to-server
     * signup integration), or without one when the list has public-subscribe: on
     * (e.g. a plain HTML <form> hosted on another website). An Authorization header
     * that IS present but wrong is rejected outright (401) rather than silently
     * falling back to the public path.
     */
    public function requestSubscribe(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $listName = $args['listname'];
        $list = $this->listProvider->getList($listName);
        if ($list === null) {
            return $this->json($response, ['error' => 'Not found'], 404);
        }

        $authHeader = $request->getHeaderLine('Authorization');
        if ($authHeader !== '') {
            $providedToken = str_starts_with($authHeader, 'Bearer ') ? substr($authHeader, 7) : '';
            if ($list->apiToken === '' || $providedToken === '' || !hash_equals($list->apiToken, $providedToken)) {
                return $this->json($response, ['error' => 'Unauthorized'], 401);
            }
        } elseif (!$list->publicSubscribe) {
            return $this->json($response, ['error' => 'Forbidden'], 403);
        }

        $body = $request->getParsedBody() ?? [];
        $mail = strtolower(trim((string) ($body['mail'] ?? '')));
        if (!filter_var($mail, FILTER_VALIDATE_EMAIL)) {
            return $this->json($response, ['error' => 'Invalid mail address'], 400);
        }

        // Always rate limit and return the same response regardless of outcome.
        if (!$this->rateLimiter->isExceeded($listName, $mail, self::MAX_SUBSCRIBE_REQUESTS_PER_10MIN)) {
            try {
                $token = $this->tokenService->sign(
                    'subscribe',
                    $listName,
                    $mail,
                    $body['firstname'] ?? null,
                    $body['lastname'] ?? null,
                    $body['username'] ?? null,
                );
                $link = "https://{$this->host}/{$listName}/subscribe/confirm?token={$token}";
                $this->sendConfirmationMail($list, $mail, $link);
            } catch (\Throwable $e) {
                error_log("Listig: Failed to send subscribe confirmation to $mail for list $listName: " . $e->getMessage());
            }
        }

        return $this->json($response, ['status' => 'confirmation_sent'], 202);
    }

    public function confirmSubscribe(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $token = $request->getQueryParams()['token'] ?? '';

        try {
            $payload = $this->tokenService->verify($token, 'subscribe', self::SUBSCRIBE_TOKEN_MAX_AGE);
        } catch (\InvalidArgumentException $e) {
            $key = $e->getMessage() === 'Token expired' ? 'subscribe.token_expired' : 'subscribe.token_invalid';
            return $this->renderConfirm($response, $key, false);
        }

        // Payload shape set by requestSubscribe() above: [listCn, mail, firstname, lastname, username]
        [$listCn, $mail, $firstname, $lastname, $username] = $payload;

        $list = $this->listProvider->getList($listCn);
        if ($list === null) {
            return $this->renderConfirm($response, 'subscribe.list_not_found', false);
        }

        $attributes = $this->attributesFromBody(['firstname' => $firstname, 'lastname' => $lastname, 'username' => $username]);

        try {
            $list->addMember(new Member($mail, $attributes));
        } catch (\RuntimeException $e) {
            error_log("Listig: subscribe confirm failed for $mail on list $listCn: " . $e->getMessage());
            return $this->renderConfirm($response, 'subscribe.failed', false, $list->language);
        }

        return $this->renderConfirm($response, 'subscribe.success', true, $list->language);
    }

    public function encryptPassword(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        /** @var ListConfig $list */
        $list = $request->getAttribute('list');
        $body = $request->getParsedBody() ?? [];
        $password = (string) ($body['password'] ?? '');

        if ($password === '') {
            return $this->json($response, ['error' => 'password is required'], 400);
        }

        $encrypted = $this->passwordCrypto->encrypt($password);

        try {
            $this->listProvider->setListConfigValue($list->name, 'mail-password', $encrypted);
        } catch (\RuntimeException $e) {
            return $this->json($response, ['error' => $e->getMessage()], 409);
        }

        return $response->withStatus(204);
    }

    private function sendConfirmationMail(ListConfig $list, string $mail, string $link): void
    {
        $locale = $list->language;
        $subject = $this->translator->trans('subscribe.confirm_mail.subject', ['%list%' => $list->displayName], null, $locale);
        $text = $this->translator->trans('subscribe.confirm_mail.body', ['%link%' => $link, '%list%' => $list->displayName], null, $locale);
        $this->notificationMailer->send($list, $mail, $subject, $text);
    }

    private function renderConfirm(ResponseInterface $response, string $messageKey, bool $success, ?string $locale = null): ResponseInterface
    {
        // Safe to mutate the translator's ambient locale here: this is the last
        // thing this request does, and each request runs in a fresh container.
        if ($locale !== null) {
            $this->translator->setLocale($locale);
        }

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/subscribe-confirm.latte', [
            'message' => $this->translator->trans($messageKey),
            'success' => $success,
            'language' => $this->translator->getLocale(),
            'translator' => $this->translator,
        ]);
        $response->getBody()->write($html);
        return $response;
    }

    private function json(ResponseInterface $response, array $data, int $status = 200): ResponseInterface
    {
        $response->getBody()->write(json_encode($data));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }

    /**
     * The API's own small, known allowlist of accepted fields — deliberately not
     * "pass the whole request body through as Member::$attributes": those
     * attribute keys can end up interpolated as SQL column names by
     * DatabaseMemberResolver::addMember() (safely validated there, but an
     * unrecognized column still throws), so accepting arbitrary external input
     * here would let a caller trivially trigger errors with a bogus body key.
     * Internally (LDAP/DB/CSV/inline config), Member::$attributes is otherwise
     * fully dynamic — see CLAUDE.md "Pronoun / salutation personalization".
     *
     * @return array<string, string>
     */
    private function attributesFromBody(array $body): array
    {
        return array_filter(
            [
                'firstname' => $body['firstname'] ?? null,
                'lastname'  => $body['lastname'] ?? null,
                'username'  => $body['username'] ?? null,
            ],
            fn($v) => $v !== null,
        );
    }
}
