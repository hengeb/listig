<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Member\AggregateMemberResolver;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\RateLimit\RateLimiter;
use Hengeb\Listig\Smtp\SmtpConnectionFactory;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Contracts\Translation\TranslatorInterface;

class AuthController
{
    private const LOGIN_TOKEN_MAX_AGE = 5 * 60;

    public function __construct(
        private readonly Engine $latte,
        private readonly TokenService $tokenService,
        private readonly RateLimiter $rateLimiter,
        private readonly AggregateMemberResolver $memberResolver,
        private readonly TranslatorInterface $translator,
        private readonly string $hostname,
        private readonly SmtpConnectionFactory $smtpConnectionFactory,
    ) {
    }

    public function showLogin(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/login.latte', [
            'flash' => $_SESSION['flash'] ?? null,
            'language' => $this->translator->getLocale(),
            'translator' => $this->translator,
        ]);
        unset($_SESSION['flash']);

        $response->getBody()->write($html);
        return $response;
    }

    public function sendMagicLink(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $body = $request->getParsedBody();
        $email = strtolower(trim($body['email'] ?? ''));

        $message = $this->translator->trans('auth.magic_link_sent');

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $_SESSION['flash'] = $message;
            return $response->withHeader('Location', '/_/login')->withStatus(302);
        }

        // Always rate limit and show same message
        $exceeded = $this->rateLimiter->isLoginExceeded($email);

        if (!$exceeded) {
            $found = $this->memberResolver->findListAndMemberByEmail($email);
            if ($found !== null) {
                ['list' => $list, 'member' => $member] = $found;
                try {
                    $token = $this->tokenService->sign('login', $list->name, $member->attributes['username'] ?? $email);
                    $link = "https://{$this->hostname}/_/login/verify?token={$token}";
                    $this->sendLoginMail($list, $member, $email, $link);
                } catch (\Throwable $e) {
                    error_log("Listig: Failed to send magic link to $email: " . $e->getMessage());
                }
            }
        }

        $_SESSION['flash'] = $message;
        return $response->withHeader('Location', '/_/login')->withStatus(302);
    }

    public function verifyToken(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $token = $request->getQueryParams()['token'] ?? '';

        try {
            $payload = $this->tokenService->verify($token, 'login', self::LOGIN_TOKEN_MAX_AGE);
        } catch (\InvalidArgumentException $e) {
            $_SESSION['flash'] = $this->translator->trans(
                $e->getMessage() === 'Token expired' ? 'auth.link_expired' : 'auth.link_invalid'
            );
            return $response->withHeader('Location', '/_/login')->withStatus(302);
        }

        // Payload shape set by sendMagicLink() above: [listCn, userCn]
        [$listCn, $userCn] = $payload;

        session_regenerate_id(true);
        $_SESSION['user'] = [
            'email' => $userCn,
            'listCn' => $listCn,
        ];

        return $response->withHeader('Location', '/')->withStatus(302);
    }

    private function sendLoginMail(ListConfig $list, Member $member, string $to, string $link): void
    {
        $firstname = $member->attributes['firstname'] ?? '';
        $lastname = $member->attributes['lastname'] ?? '';
        $name = trim("$firstname $lastname") ?: $to;

        $email = new Email();
        $email->from(new Address($list->mail, $list->displayName));
        $email->to(new Address($to));
        $email->subject($this->translator->trans('auth.login_mail.subject'));
        $email->text($this->translator->trans('auth.login_mail.body', ['%link%' => $link, '%name%' => $name]));
        $email->html($this->translator->trans('auth.login_mail.body_html', ['%link%' => $link, '%name%' => $name]));

        $transport = $this->smtpConnectionFactory->getTransport($list);
        $mailer = new Mailer($transport);
        $mailer->send($email);
    }
}
