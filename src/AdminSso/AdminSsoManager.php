<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\AdminSso;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Client\Factory as HttpFactory;
use InvalidArgumentException;
use RuntimeException;

/**
 * Client-side manager for the Admin SSO PKCE flow.
 * Used by receiving applications (PayBridge, Hadhiya, etc.) to:
 *   1. Generate PKCE pairs and build authorization URLs
 *   2. Exchange auth codes for staff identity JWTs
 *   3. Decode and validate staff identity JWTs
 */
final class AdminSsoManager
{
    public function __construct(
        private readonly HttpFactory $http,
        private readonly string $identityBridgeUrl,
        private readonly string $publicKey,
        private readonly string $internalUrl = '',
    ) {}

    private function serverUrl(): string
    {
        return rtrim($this->internalUrl ?: $this->identityBridgeUrl, '/');
    }

    /**
     * Generate a PKCE verifier/challenge pair.
     *
     * @return array{verifier: string, challenge: string}
     */
    public function generatePkce(): array
    {
        $verifier = rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '=');
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        return ['verifier' => $verifier, 'challenge' => $challenge];
    }

    /**
     * Build the IB authorization URL (app-initiated PKCE flow).
     * Redirects the admin to IB Central's login page with OAuth2 params.
     */
    public function buildAuthorizationUrl(string $clientId, string $redirectUri, string $state, string $challenge): string
    {
        $params = http_build_query([
            'response_type' => 'code',
            'client_id' => $clientId,
            'redirect_uri' => $redirectUri,
            'state' => $state,
            'code_challenge' => $challenge,
            'code_challenge_method' => 'S256',
        ]);

        return rtrim($this->identityBridgeUrl, '/').'/oauth/authorize?'.$params;
    }

    /**
     * Exchange an auth code for a staff identity JWT.
     *
     * @throws RuntimeException if the exchange fails
     */
    public function exchangeCode(string $code, string $verifier, string $redirectUri, string $clientId): string
    {
        $response = $this->http->post(
            $this->serverUrl().'/oauth/admin/token',
            [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'code_verifier' => $verifier,
                'client_id' => $clientId,
                'redirect_uri' => $redirectUri,
            ]
        );

        if (! $response->successful()) {
            throw new RuntimeException('Admin SSO token exchange failed: '.$response->body());
        }

        return $response->json('access_token');
    }

    /**
     * Decode and validate a staff identity JWT, returning typed claims.
     *
     * @throws InvalidArgumentException if the token is invalid, uses wrong algorithm, or is not a staff token
     */
    public function decodeToken(string $token): StaffClaims
    {
        // Verify algorithm before decode to prevent RS256→HS256 confusion attacks.
        // An attacker could forge a token signed with the public key as an HMAC secret
        // if we allow the library to accept whatever algorithm the header declares.
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new InvalidArgumentException('Invalid token format');
        }

        $header = json_decode(base64_decode(strtr($parts[0], '-_', '+/')), true);
        if (($header['alg'] ?? null) !== 'RS256') {
            throw new InvalidArgumentException('Token must use RS256 algorithm');
        }

        $payload = JWT::decode($token, new Key($this->publicKey, 'RS256'));

        return StaffClaims::fromPayload($payload);
    }
}
