<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Client;

use IgniteLabs\IdentityBridge\Exceptions\IdentityBridgeException;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Cache;

class IdentityBridgeClient
{
    public function __construct(
        private readonly Factory $http,
    ) {}

    public function getServiceToken(): string
    {
        $key = config('identity-bridge.cache_prefix', 'ib_sdk_').'service_token';

        if ($token = Cache::get($key)) {
            return $token;
        }

        $response = $this->http->post(
            config('identity-bridge.url').'/oauth/token',
            [
                'grant_type' => 'client_credentials',
                'client_id' => config('identity-bridge.client_id'),
                'client_secret' => config('identity-bridge.client_secret'),
            ]
        );

        if ($response->failed()) {
            $message = $response->json('message')
                ?? $response->json('error')
                ?? 'Failed to obtain service token';

            throw new IdentityBridgeException($message);
        }

        $token = $response->json('access_token');
        $ttl = config('identity-bridge.service_token_ttl', 3500);

        Cache::put($key, $token, $ttl);

        return $token;
    }

    public function getIdentity(string $identityId): array
    {
        $token = $this->getServiceToken();
        $response = $this->http
            ->withToken($token)
            ->get(config('identity-bridge.url')."/api/identities/{$identityId}");

        if ($response->status() === 404) {
            throw new IdentityBridgeException('Identity not found');
        }

        if ($response->failed()) {
            $message = $response->json('message')
                ?? $response->json('error')
                ?? 'Failed to fetch identity';

            throw new IdentityBridgeException($message);
        }

        return $response->json();
    }

    public function revokeToken(string $jti): bool
    {
        $token = $this->getServiceToken();
        $response = $this->http
            ->withToken($token)
            ->post(config('identity-bridge.url')."/api/tokens/{$jti}/revoke");

        if ($response->failed()) {
            $message = $response->json('message')
                ?? $response->json('error')
                ?? 'Failed to revoke token';

            throw new IdentityBridgeException($message);
        }

        return true;
    }

    public function refreshServiceToken(): string
    {
        $key = config('identity-bridge.cache_prefix', 'ib_sdk_').'service_token';
        Cache::forget($key);

        return $this->getServiceToken();
    }

    /**
     * Paginated list of all identities from the server.
     * Yields one page at a time: ['data' => [...], 'meta' => [...]]
     *
     * @return iterable<array{data: array, meta: array}>
     */
    public function listUsers(?string $since = null, int $perPage = 100): iterable
    {
        $page = 1;

        do {
            $query = array_filter([
                'per_page' => $perPage,
                'page' => $page,
                'since' => $since,
            ]);

            $token = $this->getServiceToken();
            $response = $this->http
                ->withToken($token)
                ->get(config('identity-bridge.url').'/api/service/users', $query);

            if ($response->failed()) {
                $message = $response->json('message')
                    ?? $response->json('error')
                    ?? 'Failed to list users';

                throw new IdentityBridgeException($message);
            }

            $body = $response->json();
            yield $body;

            $meta = $body['meta'] ?? [];
            $page++;
        } while (($meta['current_page'] ?? 1) < ($meta['last_page'] ?? 1));
    }
}
