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
        private readonly string $host,
    ) {
    }

    public function index(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $user = $request->getAttribute('user');
        $userEmail = $user['email'];

        $allLists = $this->listProvider->getLists();
        $subscribedLists = [];
        $unsubscribeLinks = [];

        foreach ($allLists as $list) {
            if (!$list->isMember($userEmail)) {
                continue;
            }
            $subscribedLists[] = $list;

            // Same mechanism MailProcessor::process() uses to build the
            // List-Unsubscribe header link — a signed, list-scoped token is the
            // only credential the /{listname}/unsubscribe endpoint accepts.
            if ($list->allowLeave === AllowLeave::Direct) {
                $member = $list->findMemberInList($userEmail);
                $token = $this->tokenService->sign(
                    'unsubscribe',
                    $list->name,
                    $member?->attributes['username'] ?? $userEmail,
                );
                $unsubscribeLinks[$list->name] = "https://{$this->host}/{$list->name}/unsubscribe?token={$token}";
            }
        }

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/dashboard.latte', [
            'user' => $user,
            'lists' => $subscribedLists,
            'unsubscribeLinks' => $unsubscribeLinks,
            'language' => $this->translator->getLocale(),
            'translator' => $this->translator,
        ]);

        $response->getBody()->write($html);
        return $response;
    }
}
