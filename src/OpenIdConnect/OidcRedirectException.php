<?php

declare(strict_types=1);

namespace Hengeb\Listig\OpenIdConnect;

/**
 * Thrown by OpenIdConnectService's OpenIDConnectClient subclass instead of the
 * library's default header()+exit, so the authorization redirect can be turned
 * into a regular PSR-7 response by the caller (AuthController::loginOidc()).
 */
class OidcRedirectException extends \Exception
{
    public function __construct(private readonly string $url)
    {
        parent::__construct('OIDC authorization redirect');
    }

    public function getUrl(): string
    {
        return $this->url;
    }
}
