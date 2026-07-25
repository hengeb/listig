<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Member\MemberResolver;
use Hengeb\Listig\RateLimit\RateLimiter;
use Hengeb\Listig\Token\TokenService;
use Latte\Engine;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Slim\Psr7\Response;
use Symfony\Component\Mailer\Mailer;
use Symfony\Component\Mailer\Transport;
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
        private readonly MemberResolver $memberResolver,
        private readonly TranslatorInterface $translator,
        private readonly string $hostname,
        private readonly string $mailerDsn,
        private readonly string $listMail,
        private readonly string $listName,
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
            $member = $this->memberResolver->findByEmail($email);
            if ($member !== null) {
                try {
                    $token = $this->tokenService->sign('login', $this->listName, $member->attributes['username'] ?? $email);
                    $link = "https://{$this->hostname}/_/login/verify?token={$token}";
                    $this->sendLoginMail($email, $link);
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

    private function sendLoginMail(string $to, string $link): void
    {
        $email = new Email();
        $email->from(new Address($this->listMail, 'Listig'));
        $email->to(new Address($to));
        $email->subject($this->translator->trans('auth.login_mail.subject'));
        $email->text($this->translator->trans('auth.login_mail.body', ['%link%' => $link]));
        $email->html($this->translator->trans('auth.login_mail.body_html', ['%link%' => $link]));

        $transport = Transport::fromDsn($this->mailerDsn);
        $mailer = new Mailer($transport);
        $mailer->send($email);
    }
}
