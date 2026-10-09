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

        $myLists = [];
        $joinableLists = [];
        $otherLists = [];
        $navigations = [];

        foreach ($this->listProvider->getLists() as $list) {
            // `visibility` decides whether a list is listed for this user at all — a plain
            // member of a `hidden` list does not see it, an outsider sees a `public` one.
            if (!$list->isVisibleTo($userEmail)) {
                continue;
            }
            // An owner who isn't also a subscribed member (a valid, real-world setup — e.g. an
            // LDAP group's owner: attribute need not overlap with its member: one) belongs to
            // "my lists" too, or /{listname} (the owner manage page) would have no entry point.
            if ($list->isMember($userEmail) || $list->isOwnedBy($userEmail)) {
                $myLists[] = $list;
            } elseif ($list->canJoin($userEmail)) {
                $joinableLists[] = $list;   // open to join, shown with a "Join" button
            } else {
                $otherLists[] = $list;      // visible, but only by invitation / on request / not addable
            }
            // Which buttons a card shows is ListActions' decision, the same one every
            // other list page uses.
            $navigations[$list->name] = $this->listActions->forViewer($list, $user);
        }

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/dashboard.latte', [
            'user' => $user,
            'lists' => $myLists,
            'joinableLists' => $joinableLists,
            'otherLists' => $otherLists,
            'navigations' => $navigations,
            'language' => $this->translator->getLocale(),
            'translator' => $this->translator,
            'appName' => $this->appName,
        ]);

        $response->getBody()->write($html);
        return $response;
    }
}
