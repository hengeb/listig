<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Config\Enum\AllowLeave;
use Hengeb\Listig\Provider\ListProvider;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

class DashboardController
{
    public function __construct(
        private readonly Engine $latte,
        private readonly ListProvider $listProvider,
        private readonly TranslatorInterface $translator,
        private readonly TokenService $tokenService,
        private readonly string $hostname,
        private readonly string $appName,
    ) {
    }

    public function index(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $userEmail = $user['email'];

        $allLists = $this->listProvider->getLists();
        $subscribedLists = [];
        $unsubscribeLinks = [];
        $listLinks = [];
        $manageLinks = [];

        foreach ($allLists as $list) {
            $isMember = $list->isMember($userEmail);
            $isOwner = $list->isOwnedBy($userEmail);

            // An owner who isn't also a subscribed member (a valid, real-world
            // setup — e.g. an LDAP group's owner: attribute need not overlap with
            // its member: one) previously never appeared here at all, since this
            // loop only ever checked isMember() — meaning /{listname} (the owner
            // manage page) had no discoverable entry point anywhere in the UI for
            // such an owner, not even via this dashboard.
            if (!$isMember && !$isOwner) {
                continue;
            }
            $subscribedLists[] = $list;

            // /{listname} now renders a reduced info page for a non-owner too
            // (see ListController::renderInfo()), not a 403 — so the card title
            // can link there for every list shown here, not just owned ones.
            // $manageLinks is the owner-only subset, used to additionally show the
            // more prominent "Manage" button (full moderation/queue/bounce view).
            $listLinks[$list->name] = "/{$list->name}";
            if ($isOwner) {
                $manageLinks[$list->name] = "/{$list->name}";
            }

            // Same mechanism MailProcessor::process() uses to build the
            // List-Unsubscribe header link — a signed, list-scoped token is the
            // only credential the /{listname}/unsubscribe endpoint accepts.
            // Only offered to an actual member — an owner-only entry has nothing
            // to unsubscribe from.
            if ($isMember && $list->allowLeave === AllowLeave::Direct && $list->supportsUnsubscribe) {
                $member = $list->findMemberInList($userEmail);
                $token = $this->tokenService->sign(
                    'unsubscribe',
                    $list->name,
                    $member?->attributes['username'] ?? $userEmail,
                );
                $unsubscribeLinks[$list->name] = "https://{$this->hostname}/{$list->name}/unsubscribe?token={$token}";
            }
        }

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/dashboard.latte', [
            'user' => $user,
            'lists' => $subscribedLists,
            'unsubscribeLinks' => $unsubscribeLinks,
            'listLinks' => $listLinks,
            'manageLinks' => $manageLinks,
            'language' => $this->translator->getLocale(),
            'translator' => $this->translator,
            'appName' => $this->appName,
        ]);

        $response->getBody()->write($html);
        return $response;
    }
}
