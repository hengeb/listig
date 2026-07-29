<?php

declare(strict_types=1);

namespace Hengeb\Listig\OpenIdConnect;

use Jumbojett\OpenIDConnectClient;

/**
 * Thin wrapper around jumbojett/openid-connect-php, driving the Authorization-Code-
 * with-PKCE flow against a discovery-capable OIDC provider (only oidc-provider-url
 * is configured — the authorization/token/userinfo endpoints and signing keys are
 * all found via the provider's /.well-known/openid-configuration).
 *
 * Only constructed (see 'oidc.enabled' / OpenIdConnectService::class in
 * config/container.php) when oidc-provider-url/oidc-client-id/oidc-client-secret
 * are all configured — see "Authentication (OIDC)" in CLAUDE.md.
 */
class OpenIdConnectService
{
    private OpenIDConnectClient $client;

    /**
     * @param string $providerUrl oidc-provider-url — the address this backend
     *        actually connects to for discovery/token/jwks/userinfo (server-to-
     *        server calls). In a Docker Compose setup this may be an internal
     *        service name/URL the IdP isn't otherwise publicly reachable at.
     * @param ?string $publicProviderHost oidc-public-provider-host — the IdP's
     *        public hostname (browser-facing), only needed when it differs from
     *        $providerUrl's own host. Some IdPs (e.g. Authelia) derive and
     *        validate their issuer strictly from the Host header +
     *        X-Forwarded-Proto of the request they receive; talking to them
     *        directly on an internal address would make them see that internal
     *        host as the issuer instead, which then fails validation against the
     *        public $redirectUrl. When set, backend requests spoof Host/
     *        X-Forwarded-Proto so the IdP treats them as coming through the
     *        public host, and non-browser-facing endpoints from the resulting
     *        discovery document (token/jwks/userinfo — necessarily also
     *        public-host-based now) are rewritten back onto $providerUrl, since
     *        those are only ever called by this backend, never the browser.
     *        authorization_endpoint is left untouched — it's returned to the
     *        browser via redirect and must stay public. Null (default): no
     *        spoofing, $providerUrl is used as-is everywhere and assumed
     *        directly reachable from both the browser and this backend.
     * @param ?string $logoutUrlOverride oidc-logout-url — used verbatim (no
     *        parameters appended) instead of discovery when set, for providers
     *        that don't implement a standard, spec-compliant end_session_endpoint
     *        (e.g. Authelia, which has its own non-standard logout page/params).
     *        See getLogoutUrl().
     */
    public function __construct(
        string $providerUrl,
        string $clientId,
        string $clientSecret,
        string $redirectUrl,
        ?string $publicProviderHost = null,
        private readonly ?string $logoutUrlOverride = null,
    ) {
        // capture the authorization redirect instead of header()+exit so it fits
        // AuthController::loginOidc()'s normal PSR-7 response flow
        $this->client = new class($providerUrl, $clientId, $clientSecret, $publicProviderHost) extends OpenIDConnectClient {
            public function __construct(
                string $providerUrl,
                string $clientId,
                string $clientSecret,
                private readonly ?string $publicProviderHost,
            ) {
                parent::__construct($providerUrl, $clientId, $clientSecret);
            }

            public function redirect(string $url): never
            {
                throw new OidcRedirectException($url);
            }

            protected function fetchURL(string $url, ?string $post_body = null, array $headers = []): bool|string
            {
                if ($this->publicProviderHost !== null) {
                    $headers[] = 'Host: ' . $this->publicProviderHost;
                    $headers[] = 'X-Forwarded-Proto: https';
                }
                return parent::fetchURL($url, $post_body, $headers);
            }

            /** @return string|string[]|bool */
            protected function getProviderConfigValue(string $param, $default = null)
            {
                $value = parent::getProviderConfigValue($param, $default);
                if ($this->publicProviderHost !== null && is_string($value)
                    && in_array($param, ['token_endpoint', 'jwks_uri', 'userinfo_endpoint'], true)
                ) {
                    $value = rtrim($this->getProviderURL(), '/') . parse_url($value, PHP_URL_PATH);
                }
                return $value;
            }
        };
        $this->client->setRedirectURL($redirectUrl);
        // jumbojett always appends the mandatory "openid" scope itself. Only "email"
        // is requested beyond that — it's the only claim getUserInfo() ever reads
        // (AuthController::loginOidc()); no code path consumes anything "profile"
        // would add (name, given_name, family_name, preferred_username, ...).
        $this->client->addScope(['email']);
        $this->client->setCodeChallengeMethod('S256');
    }

    /**
     * Drives the OIDC flow against the current request (relies on $_GET/$_REQUEST,
     * same as the underlying library):
     *  - on the initial request (no ?code/?error yet): returns the authorization URL
     *    to redirect the browser to
     *  - on the callback (?code present): validates the tokens and returns null
     *
     * @throws \Jumbojett\OpenIDConnectClientException on validation errors or an
     *         error response from the IdP (e.g. ?error=access_denied) — caller
     *         decides how to surface this, see AuthController::loginOidc()
     */
    public function authenticate(): ?string
    {
        try {
            $this->client->authenticate();
        } catch (OidcRedirectException $e) {
            return $e->getUrl();
        }

        return null;
    }

    /**
     * Reads a claim from the verified ID token first, falling back to the userinfo
     * endpoint for claims the ID token doesn't carry (provider-dependent) — only
     * meaningful after authenticate() has returned null (i.e. the callback leg).
     */
    public function getUserInfo(string $claim): ?string
    {
        $value = $this->client->getVerifiedClaims($claim) ?? $this->client->requestUserInfo($claim);
        return $value !== null ? (string) $value : null;
    }

    /**
     * The raw ID token from the last successful authenticate() callback — save
     * this in the session (AuthController::loginOidc()) so a later logout can
     * pass it as id_token_hint; the token itself is opaque to Listig otherwise.
     */
    public function getIdToken(): ?string
    {
        return $this->client->getIdToken();
    }

    /**
     * Builds the URL to redirect the browser to for IdP-side (RP-initiated)
     * logout, so a Listig logout doesn't leave the user silently re-authenticated
     * by the IdP's own still-valid session on the next OIDC login. Returns null
     * if this can't be done — no oidc-logout-url override configured and the
     * provider's discovery document has no end_session_endpoint (not every IdP
     * implements RP-initiated logout) — AuthController::logout() falls back to a
     * purely local logout in that case.
     */
    public function getLogoutUrl(string $idToken, string $postLogoutRedirectUri): ?string
    {
        if ($this->logoutUrlOverride !== null) {
            return $this->logoutUrlOverride;
        }

        try {
            $this->client->signOut($idToken, $postLogoutRedirectUri);
        } catch (OidcRedirectException $e) {
            return $e->getUrl();
        } catch (\Jumbojett\OpenIDConnectClientException $e) {
            return null;
        }

        return null;
    }
}
