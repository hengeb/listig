<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Http\ListActions;
use Hengeb\Listig\Mail\ReplyTargetStore;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\RateLimit\RateLimiter;
use Latte\Engine;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Exception\HttpNotFoundException;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * Web form for a first mail to an external address, sent as the list (see docs/architecture/masked-replies.md
 * "Masked reply addresses"). Does not send anything itself: it only issues the signed
 * `{localPart}+r-{TOKEN}@{domain}` address for the entered recipient and hands back a
 * `mailto:` link, so the member writes the mail in their usual mail client; the reply
 * pipeline then relays it From the list address.
 *
 * Deliberately shows no list of previous contacts: that would reveal external
 * addresses to members who never dealt with them, on lists that mask them on purpose.
 */
class ComposeController
{
    private const int MAX_PER_10_MIN = 20;

    public function __construct(
        private readonly Engine $latte,
        private readonly ListProvider $listProvider,
        private readonly ReplyTargetStore $replyTargetStore,
        private readonly RateLimiter $rateLimiter,
        private readonly ListActions $listActions,
        private readonly TranslatorInterface $translator,
        private readonly string $appName,
    ) {
    }

    public function show(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $list = $this->listProvider->getList($args['listname']);
        if ($list === null || !$list->canComposeExternal($user['email'])) {
            throw new HttpNotFoundException($request);
        }

        $this->translator->setLocale($list->language);
        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/compose.latte', [
            'user' => $user,
            'list' => $list,
            'nav' => $this->listActions->forViewer($list, $user, 'compose'),
            'language' => $list->language,
            'translator' => $this->translator,
            'appName' => $this->appName,
        ]);
        $response->getBody()->write($html);
        return $response;
    }

    /** POST /_/api/compose/{listname}, JSON body {"mail": "..."} → {"mailto": "..."}. */
    public function createAddress(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $list = $this->listProvider->getList($args['listname']);
        if ($list === null || !$list->canComposeExternal($user['email'])) {
            return $this->json($response, ['error' => 'not found'], 404);
        }
        $this->translator->setLocale($list->language);

        // Each call may create a reply_targets row — bounded per user and list.
        if ($this->rateLimiter->isExceeded($list->name, '__compose__:' . $user['email'], self::MAX_PER_10_MIN)) {
            return $this->json($response, ['error' => $this->translator->trans('compose.error_rate_limited')], 429);
        }

        $body = json_decode((string) $request->getBody(), true);
        $mail = is_array($body) ? trim((string) ($body['mail'] ?? '')) : '';
        if (filter_var($mail, FILTER_VALIDATE_EMAIL) === false
            || strcasecmp($mail, $list->mail) === 0
            || str_ends_with(strtolower($mail), '.invalid')) {
            return $this->json($response, ['error' => $this->translator->trans('compose.error_invalid_address')], 422);
        }

        $token = $this->replyTargetStore->tokenFor($list, $mail);
        return $this->json($response, ['mailto' => "mailto:{$list->localPart}+r-{$token}@{$list->domain}"]);
    }

    private function json(ResponseInterface $response, array $data, int $status = 200): ResponseInterface
    {
        $response->getBody()->write(json_encode($data));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
