<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Http\ListActions;
use Hengeb\Listig\Provider\ListProvider;
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
        private readonly ListActions $listActions,
        private readonly string $appName,
    ) {
    }

    public function index(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $userEmail = $user['email'];

        $subscribedLists = [];
        $navigations = [];

        foreach ($this->listProvider->getLists() as $list) {
            // An owner who isn't also a subscribed member (a valid, real-world
            // setup — e.g. an LDAP group's owner: attribute need not overlap with
            // its member: one) must appear here too, or /{listname} (the owner
            // manage page) would have no discoverable entry point for them.
            if (!$list->isMember($userEmail) && !$list->isOwnedBy($userEmail)) {
                continue;
            }
            $subscribedLists[] = $list;
            // Which buttons a card shows is ListActions' decision, the same one every
            // other list page uses.
            $navigations[$list->name] = $this->listActions->forViewer($list, $user);
        }

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/dashboard.latte', [
            'user' => $user,
            'lists' => $subscribedLists,
            'navigations' => $navigations,
            'language' => $this->translator->getLocale(),
            'translator' => $this->translator,
            'appName' => $this->appName,
        ]);

        $response->getBody()->write($html);
        return $response;
    }
}
