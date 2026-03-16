<?php

declare(strict_types=1);

use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Exceptions\IdentityBridgeException;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(
            ['access_token' => 'svc-token', 'expires_in' => 3600], 200
        ),
    ]);
});

it('yields a single page when last_page equals 1', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/service/users*' => Http::response([
            'data' => [
                ['identity_id' => 'uuid-1', 'kyc_tier' => 1, 'created_at' => '2026-01-01T00:00:00Z'],
                ['identity_id' => 'uuid-2', 'kyc_tier' => 2, 'created_at' => '2026-01-02T00:00:00Z'],
            ],
            'meta' => ['total' => 2, 'per_page' => 100, 'current_page' => 1, 'last_page' => 1],
        ], 200),
    ]);

    $client = app(IdentityBridgeClient::class);
    $pages = iterator_to_array($client->listUsers());

    expect($pages)->toHaveCount(1)
        ->and($pages[0]['data'])->toHaveCount(2)
        ->and($pages[0]['data'][0]['identity_id'])->toBe('uuid-1');
});

it('iterates multiple pages until last_page is reached', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/service/users*' => Http::sequence()
            ->push([
                'data' => [['identity_id' => 'uuid-1', 'kyc_tier' => 1, 'created_at' => '2026-01-01T00:00:00Z']],
                'meta' => ['total' => 2, 'per_page' => 1, 'current_page' => 1, 'last_page' => 2],
            ], 200)
            ->push([
                'data' => [['identity_id' => 'uuid-2', 'kyc_tier' => 2, 'created_at' => '2026-01-02T00:00:00Z']],
                'meta' => ['total' => 2, 'per_page' => 1, 'current_page' => 2, 'last_page' => 2],
            ], 200),
    ]);

    $client = app(IdentityBridgeClient::class);
    $pages = iterator_to_array($client->listUsers(perPage: 1));

    expect($pages)->toHaveCount(2)
        ->and($pages[0]['data'][0]['identity_id'])->toBe('uuid-1')
        ->and($pages[1]['data'][0]['identity_id'])->toBe('uuid-2');
});

it('passes since parameter to the server', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/service/users*' => Http::response([
            'data' => [],
            'meta' => ['total' => 0, 'per_page' => 100, 'current_page' => 1, 'last_page' => 1],
        ], 200),
    ]);

    $client = app(IdentityBridgeClient::class);
    iterator_to_array($client->listUsers(since: '2026-01-01T00:00:00Z'));

    Http::assertSent(fn ($req) => str_contains($req->url(), 'since='));
});

it('throws IdentityBridgeException on HTTP error', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/service/users*' => Http::response(['error' => 'Forbidden'], 403),
    ]);

    $client = app(IdentityBridgeClient::class);

    expect(fn () => iterator_to_array($client->listUsers()))
        ->toThrow(IdentityBridgeException::class);
});
