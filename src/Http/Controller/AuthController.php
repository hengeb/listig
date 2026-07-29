<?php

declare(strict_types=1);

namespace Hengeb\Listig\Http\Controller;

use Hengeb\Listig\Config\ListConfig;
use Hengeb\Listig\Logging\Logger;
use Hengeb\Listig\Member\AggregateMemberResolver;
use Hengeb\Listig\Member\Member;
use Hengeb\Listig\OpenIdConnect\OpenIdConnectService;
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
        private readonly string $appName,
        private readonly ListConfig $defaultSmtpConfig,
        private readonly Logger $logger,
        private readonly bool $oidcEnabled = false,
        private readonly ?OpenIdConnectService $openIdConnect = null,
    ) {
    }

    public function showLogin(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $html = $this->latte->renderToString(__DIR__ . '/../../../templates/login.latte', [
            'flash' => $_SESSION['flash'] ?? null,
            'language' => $this->translator->getLocale(),
            'translator' => $this->translator,
            'oidcEnabled' => $this->oidcEnabled,
            'appName' => $this->appName,
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

        $this->logger->debug("Listig: login requested for $email");

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
                    $this->logger->debug("Listig: login link sent to $email for list {$list->name}", $list->logLevel);
                } catch (\Throwable $e) {
                    error_log("Listig: Failed to send magic link to $email: " . $e->getMessage());
                }
            } else {
                $this->logger->debug("Listig: login requested for $email — no matching member found in any list");
            }
        } else {
            $this->logger->debug("Listig: login requested for $email — rate limit exceeded");
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

        $this->logger->debug("Listig: login successful for $userCn (list $listCn)");

        return $response->withHeader('Location', '/')->withStatus(302);
    }

    /**
     * Single route for both the OIDC login initiation and the callback (its own
     * redirect_uri) — only registered at all when 'oidc.enabled' is true (see
     * public/index.php), so $this->openIdConnect is never null here.
     */
    public function loginOidc(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        try {
            $redirectUrl = $this->openIdConnect->authenticate();
        } catch (\Throwable $e) {
            error_log('Listig: OIDC authentication failed: ' . $e->getMessage());
            $_SESSION['flash'] = $this->translator->trans('auth.oidc_failed');
            return $response->withHeader('Location', '/_/login')->withStatus(302);
        }

        // Initial request — not a callback yet: redirect the browser to the IdP.
        if ($redirectUrl !== null) {
            return $response->withHeader('Location', $redirectUrl)->withStatus(302);
        }

        // Callback: tokens are validated at this point (the library already threw
        // above otherwise) — resolve the verified email to a list member exactly
        // like the magic-link flow does (AggregateMemberResolver searches every
        // configured list), rather than trusting the IdP's own notion of identity
        // beyond "this really is the owner of this email address".
        $email = strtolower(trim((string) $this->openIdConnect->getUserInfo('email')));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $_SESSION['flash'] = $this->translator->trans('auth.oidc_no_email');
            return $response->withHeader('Location', '/_/login')->withStatus(302);
        }

        $found = $this->memberResolver->findListAndMemberByEmail($email);
        if ($found === null) {
            $_SESSION['flash'] = $this->translator->trans('auth.oidc_not_found');
            return $response->withHeader('Location', '/_/login')->withStatus(302);
        }

        ['list' => $list, 'member' => $member] = $found;

        session_regenerate_id(true);
        $_SESSION['user'] = [
            'email' => $member->attributes['username'] ?? $member->email,
            'listCn' => $list->name,
        ];
        $this->logger->debug("Listig: OIDC login successful for $email (list {$list->name})", $list->logLevel);
        // Saved so logout() can pass it back as id_token_hint for RP-initiated
        // logout — otherwise a Listig logout would leave the user silently
        // re-authenticated by the IdP's own still-valid session on next login.
        $_SESSION['oidcIdToken'] = $this->openIdConnect->getIdToken();

        return $response->withHeader('Location', '/')->withStatus(302);
    }

    /**
     * Always returns 200 + JSON {"redirectUrl": "..."} rather than a plain 204 —
     * a magic-link session redirects to "/_/login" same as before, but an OIDC
     * session may need to redirect the browser on to the IdP's own logout page
     * first (see OpenIdConnectService::getLogoutUrl()), which the client-side
     * fetch() in layout.latte can't distinguish from a same-origin 204 alone.
     */
    public function logout(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }

        $oidcIdToken = $_SESSION['oidcIdToken'] ?? null;

        $_SESSION = [];
        session_destroy();

        $redirectUrl = '/_/login';
        if ($oidcIdToken !== null && $this->openIdConnect !== null) {
            // The local session is already gone at this point regardless — a
            // failure here (IdP unreachable, discovery error, ...) must still
            // leave the user logged out of Listig, just without IdP-side logout.
            try {
                $redirectUrl = $this->openIdConnect->getLogoutUrl($oidcIdToken, "https://{$this->hostname}/_/login") ?? $redirectUrl;
            } catch (\Throwable $e) {
                error_log('Listig: OIDC logout failed: ' . $e->getMessage());
            }
        }

        $response->getBody()->write(json_encode(['redirectUrl' => $redirectUrl]));
        return $response->withStatus(200)->withHeader('Content-Type', 'application/json');
    }

    private function sendLoginMail(ListConfig $list, Member $member, string $to, string $link): void
    {
        $firstname = $member->attributes['firstname'] ?? '';
        $lastname = $member->attributes['lastname'] ?? '';
        $name = trim("$firstname $lastname") ?: $to;

        // A login mail is a system-level action, not a per-list one — prefer the
        // config.yml root's own SMTP identity (mail-user/mail-host, resolved
        // independent of any list-provider/list override, see 'app.default-smtp-
        // config' in container.php) so it doesn't appear to come from whichever
        // list the member happens to be matched against. Falls back to the
        // matched list's own SMTP config only if no root-level default exists at
        // all (smtp-host/mail-host never set anywhere at the config.yml root).
        $useDefault = $this->defaultSmtpConfig->smtpHost !== '';
        $senderList = $useDefault ? $this->defaultSmtpConfig : $list;
        $fromAddress = $useDefault ? $this->defaultSmtpConfig->smtpUser : $list->mail;
        $fromName = $useDefault ? $this->appName : $list->displayName;

        $email = new Email();
        $email->from(new Address($fromAddress, $fromName));
        $email->to(new Address($to));
        $email->subject($this->translator->trans('auth.login_mail.subject', ['%app_name%' => $this->appName]));
        $email->text($this->translator->trans('auth.login_mail.body', ['%link%' => $link, '%name%' => $name]));
        $email->html($this->translator->trans('auth.login_mail.body_html', ['%link%' => $link, '%name%' => $name]));

        $transport = $this->smtpConnectionFactory->getTransport($senderList);
        $mailer = new Mailer($transport);
        $mailer->send($email);
    }
}
