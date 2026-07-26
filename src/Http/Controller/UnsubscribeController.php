<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Config\Enum\AllowLeave;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Mail\NotificationMailer;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

class UnsubscribeController
{
    private const UNSUBSCRIBE_TOKEN_MAX_AGE = 7 * 24 * 3600;

    public function __construct(
        private readonly Engine $latte,
        private readonly TokenService $tokenService,
        private readonly ListProvider $listProvider,
        private readonly NotificationMailer $notificationMailer,
        private readonly TranslatorInterface $translator,
        private readonly string $appName,
    ) {
    }

    public function unsubscribe(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $token = $request->getQueryParams()['token'] ?? '';

        try {
            $payload = $this->tokenService->verify($token, 'unsubscribe', self::UNSUBSCRIBE_TOKEN_MAX_AGE);
        } catch (\InvalidArgumentException $e) {
            // No list known yet (token may not even decode) — use the global default locale.
            $key = $e->getMessage() === 'Token expired' ? 'unsubscribe.token_expired' : 'unsubscribe.token_invalid';
            return $this->render($response, $key, [], false);
        }

        // Payload shape set by MailProcessor::process(): [listCn, userCn]
        [$listCn, $userCn] = $payload;

        // The {listname} URL segment is not itself trusted for anything — the token
        // payload is the sole source of truth for which list this is — but a mismatch
        // means a stale/copy-pasted URL, so reject it the same way as a bad signature
        // rather than silently using the token's listCn instead.
        if (strtolower((string) ($args['listname'] ?? '')) !== strtolower($listCn)) {
            return $this->render($response, 'unsubscribe.token_invalid', [], false);
        }

        $list = $this->listProvider->getList($listCn);
        if ($list === null) {
            return $this->render($response, 'unsubscribe.list_not_found', [], false);
        }

        // Resolve the actual email address from userCn (may be username or email)
        $member = $list->findMemberByEmail($userCn);
        $memberEmail = $member?->email ?? $userCn;

        if ($list->allowLeave === AllowLeave::Moderated) {
            $this->notifyOwners($list, $member, $memberEmail);
            return $this->render($response, 'unsubscribe.moderated_notice', [], true, $list->language);
        }

        // Direct unsubscribe — remove and show success regardless of whether
        // $memberEmail was actually still a member (prevents enumeration). But if
        // the list's member store can't persist a removal at all (static inline
        // config.yml members, or no store configured), that's a list-wide,
        // non-address-specific fact — safe to reveal, and better than a false
        // "success" that leaves the member subscribed forever.
        if (!$list->supportsUnsubscribe) {
            return $this->render($response, 'unsubscribe.not_supported', [], false, $list->language);
        }

        try {
            $list->removeMember($memberEmail);
        } catch (\RuntimeException $e) {
            error_log("Listig: Unsubscribe failed for list {$list->name}: " . $e->getMessage());
            return $this->render($response, 'unsubscribe.not_supported', [], false, $list->language);
        }

        return $this->render($response, 'unsubscribe.success', [], true, $list->language);
    }

    private function notifyOwners(ListConfig $list, mixed $member, string $memberEmail): void
    {
        $firstname = $member?->attributes['firstname'] ?? '';
        $lastname = $member?->attributes['lastname'] ?? '';
        $displayName = trim("$firstname $lastname") ?: $memberEmail;
        $locale = $list->language;

        $this->notificationMailer->sendToOwners(
            $list,
            $this->translator->trans('unsubscribe.owner_notice.subject', [
                '%list%' => $list->displayName,
                '%name%' => $displayName,
            ], null, $locale),
            $this->translator->trans('unsubscribe.owner_notice.body', [
                '%name%' => $displayName,
                '%mail%' => $memberEmail,
                '%list%' => $list->displayName,
            ], null, $locale),
        );
    }

    private function render(ResponseInterface $response, string $messageKey, array $messageParams, bool $success, ?string $locale = null): ResponseInterface
    {
        // Setting the translator's locale here is safe: this is the last thing this
        // request does, and each request runs in a fresh container (Slim, no
        // long-running worker), so there is no risk of leaking it into later code.
        if ($locale !== null) {
            $this->translator->setLocale($locale);
        }

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/unsubscribe.latte', [
            'message' => $this->translator->trans($messageKey, $messageParams),
            'success' => $success,
            'language' => $this->translator->getLocale(),
            'translator' => $this->translator,
            'appName' => $this->appName,
        ]);
        $response->getBody()->write($html);
        return $response;
    }
}
