<?php

use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Exceptions\IdentityBridgeException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    Cache::flush();
});

it('returns cached token when available', function () {
    Cache::put('ib_sdk_service_token', 'cached-token-abc', 3500);

    Http::fake();

    $client = $this->app->make(IdentityBridgeClient::class);
    $token = $client->getServiceToken();

    expect($token)->toBe('cached-token-abc');
    Http::assertNothingSent();
});

it('fetches fresh token when cache is empty', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response([
            'access_token' => 'fresh-token-xyz',
            'expires_in' => 3600,
        ], 200),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);
    $token = $client->getServiceToken();

    expect($token)->toBe('fresh-token-xyz');
});

it('caches the access_token from response', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response([
            'access_token' => 'stored-token-999',
            'expires_in' => 3600,
        ], 200),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);
    $client->getServiceToken();

    expect(Cache::get('ib_sdk_service_token'))->toBe('stored-token-999');
});

it('caches token with configured TTL', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response([
            'access_token' => 'ttl-token',
            'expires_in' => 3600,
        ], 200),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);
    $client->getServiceToken();

    // Verify it is still cached (TTL is 3500s, well within range)
    expect(Cache::get('ib_sdk_service_token'))->toBe('ttl-token');
});

it('uses prefix+service_token as the cache key', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response([
            'access_token' => 'prefix-token',
        ], 200),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);
    $client->getServiceToken();

    expect(Cache::get('ib_sdk_service_token'))->toBe('prefix-token');
    expect(Cache::get('service_token'))->toBeNull();
});

it('throws IdentityBridgeException on HTTP error fetching service token', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response([
            'message' => 'Unauthorized client',
        ], 401),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);

    expect(fn () => $client->getServiceToken())
        ->toThrow(IdentityBridgeException::class, 'Unauthorized client');
});

it('getIdentity returns decoded JSON array', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/identities/*' => Http::response(['sub' => 'uuid-123', 'kyc_tier' => 2], 200),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);
    $result = $client->getIdentity('uuid-123');

    expect($result)->toBe(['sub' => 'uuid-123', 'kyc_tier' => 2]);
});

it('getIdentity calls the correct endpoint with Bearer token', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'bearer-tok'], 200),
        'https://identity.ignitlabs.mv/api/identities/some-identity-id' => Http::response(['sub' => 'some-identity-id'], 200),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);
    $client->getIdentity('some-identity-id');

    Http::assertSent(function ($request) {
        return $request->url() === 'https://identity.ignitlabs.mv/api/identities/some-identity-id'
            && $request->hasHeader('Authorization', 'Bearer bearer-tok');
    });
});

it('getIdentity throws IdentityBridgeException on 404', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/identities/*' => Http::response(['message' => 'Not Found'], 404),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);

    expect(fn () => $client->getIdentity('missing-id'))
        ->toThrow(IdentityBridgeException::class, 'Identity not found');
});

it('getIdentity throws IdentityBridgeException on other HTTP errors', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/identities/*' => Http::response(['message' => 'Server error'], 500),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);

    expect(fn () => $client->getIdentity('some-id'))
        ->toThrow(IdentityBridgeException::class);
});

it('revokeToken returns true on success', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/tokens/*/revoke' => Http::response([], 200),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);

    expect($client->revokeToken('some-jti'))->toBeTrue();
});

it('revokeToken returns true on 204', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/tokens/*/revoke' => Http::response([], 204),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);

    expect($client->revokeToken('some-jti'))->toBeTrue();
});

it('revokeToken throws IdentityBridgeException on error', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/tokens/*/revoke' => Http::response(['message' => 'Forbidden'], 403),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);

    expect(fn () => $client->revokeToken('some-jti'))
        ->toThrow(IdentityBridgeException::class);
});

it('refreshServiceToken clears cache and fetches fresh token', function () {
    Cache::put('ib_sdk_service_token', 'old-stale-token', 3500);

    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response([
            'access_token' => 'brand-new-token',
        ], 200),
    ]);

    $client = $this->app->make(IdentityBridgeClient::class);
    $token = $client->refreshServiceToken();

    expect($token)->toBe('brand-new-token');
    expect(Cache::get('ib_sdk_service_token'))->toBe('brand-new-token');
});
