<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Config\Enum\JoinPolicy;
use Hengeb\Listig\Member\AggregateMemberResolver;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\RateLimit\RateLimiter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

/**
 * The "Join" button of `join-policy: open` lists: `POST /_/api/join/{listname}` (behind
 * AuthMiddleware + CSRF) adds the logged-in user — whose address the login already confirmed,
 * so there is no confirmation mail — as a member. See docs/adr/0021-join-policy-and-visibility.md.
 */
class JoinController
{
    private const int MAX_PER_10_MIN = 10;

    /** Same small fixed allowlist as the List Management API (ListApiController::attributesFromBody()). */
    private const array ATTRIBUTES = ['firstname', 'lastname', 'username'];

    public function __construct(
        private readonly ListProvider $listProvider,
        private readonly AggregateMemberResolver $memberResolver,
        private readonly RateLimiter $rateLimiter,
        private readonly TranslatorInterface $translator,
    ) {
    }

    public function join(ServerRequestInterface $request, ResponseInterface $response, array $args): ResponseInterface
    {
        $email = $request->getAttribute('user')['email'];
        $list = $this->listProvider->getList($args['listname']);
        // A list the user may not see does not exist for them.
        if ($list === null || !$list->isVisibleTo($email)) {
            return $this->json($response, ['error' => 'not found'], 404);
        }
        if ($list->joinPolicy !== JoinPolicy::Open) {
            return $this->json($response, ['error' => $this->translator->trans('join.error_not_open', [], null, $list->language)], 403);
        }
        if ($list->isMember($email)) {
            return $this->json($response, ['status' => 'ok']); // idempotent
        }
        if (!$list->supportsJoin) {
            return $this->json($response, ['error' => $this->translator->trans('join.error_unsupported', [], null, $list->language)], 409);
        }
        if ($this->rateLimiter->isExceeded($list->name, '__join__:' . $email, self::MAX_PER_10_MIN)) {
            return $this->json($response, ['error' => $this->translator->trans('join.error_rate_limited', [], null, $list->language)], 429);
        }

        // Carry over the user's own name/username from whichever list they logged in through.
        $known = $this->memberResolver->findListAndMemberByEmail($email)['member'] ?? null;
        $attributes = array_intersect_key($known->attributes ?? [], array_flip(self::ATTRIBUTES));

        try {
            $list->addMember(new Member($email, $attributes));
        } catch (\RuntimeException $e) {
            error_log("Listig: join failed for {$email} on list {$list->name}: " . $e->getMessage());
            return $this->json($response, ['error' => $this->translator->trans('join.error_failed', [], null, $list->language)], 409);
        }

        return $this->json($response, ['status' => 'ok']);
    }

    private function json(ResponseInterface $response, array $data, int $status = 200): ResponseInterface
    {
        $response->getBody()->write(json_encode($data));
        return $response->withStatus($status)->withHeader('Content-Type', 'application/json');
    }
}
