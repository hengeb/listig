<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Config\Enum\AllowLeave;
use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Member\LeaveOutcome;
use Hengeb\Listig\Member\ListLeaver;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\LocaleAwareInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The unsubscribe link of a mail footer / `List-Unsubscribe` header (`/{listname}/unsubscribe?token=…`).
 * Only a POST changes anything: a GET merely shows a confirmation page, because link scanners and
 * mail-client previews fetch URLs with GET and must never unsubscribe anybody. The POST is also what
 * RFC 8058 one-click mail clients send to the `List-Unsubscribe` URL
 * (`List-Unsubscribe-Post: List-Unsubscribe=One-Click`). See docs/adr/0022-unsubscribe-links-act-on-post.md.
 */
class UnsubscribeController
{
    private const UNSUBSCRIBE_TOKEN_MAX_AGE = 7 * 24 * 3600;

    public function __construct(
        private readonly Engine $latte,
        private readonly TokenService $tokenService,
        private readonly ListProvider $listProvider,
        private readonly ListLeaver $listLeaver,
        private readonly TranslatorInterface $translator,
        private readonly string $appName,
    ) {
    }

    /** GET: show what would happen and a button; nothing is changed. */
    public function show(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $resolved = $this->resolve($request, $response, $args);
        if ($resolved instanceof ResponseInterface) {
            return $resolved;
        }
        ['list' => $list] = $resolved;

        $this->useLocale($list->language);
        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/unsubscribe-confirm.latte', [
            'list' => $list,
            'moderated' => $list->allowLeave === AllowLeave::Moderated,
            // Same URL, with the token — the form POSTs back to it.
            'action' => $request->getUri()->getPath() . '?token=' . rawurlencode((string) ($request->getQueryParams()['token'] ?? '')),
            'language' => $list->language,
            'translator' => $this->translator,
            'appName' => $this->appName,
        ]);
        $response->getBody()->write($html);
        return $response;
    }

    /** POST: the confirmation form, or an RFC 8058 one-click request. */
    public function execute(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $resolved = $this->resolve($request, $response, $args);
        if ($resolved instanceof ResponseInterface) {
            return $resolved;
        }
        ['list' => $list, 'userCn' => $userCn] = $resolved;

        // Resolve the actual email address from userCn (may be username or email —
        // see docs/architecture/providers-and-members.md "Privacy-preserving username"). findMemberByEmail() only
        // ever matches Member::$email (an LDAP `(mail=$userCn)` search never finds
        // anything when $userCn is actually the LDAP cn), so it cannot reverse this
        // lookup — findMemberInListByUserCn() mirrors exactly how the token's
        // identifier was derived when it was signed.
        $member = $list->findMemberInListByUserCn($userCn);
        $outcome = $this->listLeaver->leave($list, $member, $member?->email ?? $userCn);

        return match ($outcome) {
            LeaveOutcome::Requested => $this->render($response, 'unsubscribe.moderated_notice', true, $list->language),
            LeaveOutcome::NotSupported => $this->render($response, 'unsubscribe.not_supported', false, $list->language),
            LeaveOutcome::Left => $this->render($response, 'unsubscribe.success', true, $list->language),
        };
    }

    /** @return array{list: ListConfig, userCn: string}|ResponseInterface the error page when the link is unusable */
    private function resolve(ServerRequestInterface $request, ResponseInterface $response, array $args): array|ResponseInterface
    {
        $token = $request->getQueryParams()['token'] ?? '';

        try {
            $payload = $this->tokenService->verify($token, 'u', self::UNSUBSCRIBE_TOKEN_MAX_AGE);
        } catch (\InvalidArgumentException $e) {
            // No list known yet (token may not even decode) — use the global default locale.
            $key = $e->getMessage() === 'Token expired' ? 'unsubscribe.token_expired' : 'unsubscribe.token_invalid';
            return $this->render($response, $key, false);
        }

        // Payload shape set by MailProcessor::process(): [listCn, userCn]
        [$listCn, $userCn] = $payload;

        // The {listname} URL segment is not itself trusted for anything — the token
        // payload is the sole source of truth for which list this is — but a mismatch
        // means a stale/copy-pasted URL, so reject it the same way as a bad signature
        // rather than silently using the token's listCn instead.
        if (strtolower((string) ($args['listname'] ?? '')) !== strtolower($listCn)) {
            return $this->render($response, 'unsubscribe.token_invalid', false);
        }

        $list = $this->listProvider->getList($listCn);
        if ($list === null) {
            return $this->render($response, 'unsubscribe.list_not_found', false);
        }

        return ['list' => $list, 'userCn' => $userCn];
    }

    private function useLocale(string $locale): void
    {
        if ($this->translator instanceof LocaleAwareInterface) {
            $this->translator->setLocale($locale);
        }
    }

    private function render(ResponseInterface $response, string $messageKey, bool $success, ?string $locale = null): ResponseInterface
    {
        // Setting the translator's locale here is safe: this is the last thing this
        // request does, and each request runs in a fresh container (Slim, no
        // long-running worker), so there is no risk of leaking it into later code.
        if ($locale !== null) {
            $this->useLocale($locale);
        }

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/unsubscribe.latte', [
            'message' => $this->translator->trans($messageKey),
            'success' => $success,
            'language' => $this->translator->getLocale(),
            'translator' => $this->translator,
            'appName' => $this->appName,
        ]);
        $response->getBody()->write($html);
        return $response;
    }
}
