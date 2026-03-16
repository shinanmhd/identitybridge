<?php

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    Http::preventStrayRequests();
});

it('outputs success messages when health endpoint returns 200 and token is obtained', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/health' => Http::response([], 200),
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'tok_abc'], 200),
    ]);

    $this->artisan('identity-bridge:check')
        ->expectsOutputToContain('✓ Identity Bridge is reachable at https://identity.ignitlabs.mv')
        ->expectsOutputToContain('✓ Service token obtained successfully')
        ->assertExitCode(0);
});

it('outputs error and exits 1 when health endpoint returns non-200', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/health' => Http::response([], 503),
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'tok_abc'], 200),
    ]);

    $this->artisan('identity-bridge:check')
        ->expectsOutputToContain('✗ Cannot reach Identity Bridge at https://identity.ignitlabs.mv')
        ->assertExitCode(1);
});

it('outputs error and exits 1 when health endpoint throws a connection exception', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/health' => fn () => throw new ConnectionException('Connection refused'),
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'tok_abc'], 200),
    ]);

    $this->artisan('identity-bridge:check')
        ->expectsOutputToContain('✗ Cannot reach Identity Bridge at https://identity.ignitlabs.mv')
        ->assertExitCode(1);
});

it('outputs health success but token error and exits 1 when getServiceToken fails', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/health' => Http::response([], 200),
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['error' => 'unauthorized'], 401),
    ]);

    $this->artisan('identity-bridge:check')
        ->expectsOutputToContain('✓ Identity Bridge is reachable at https://identity.ignitlabs.mv')
        ->expectsOutputToContain('✗ Failed to obtain service token:')
        ->assertExitCode(1);
});

it('uses the configured url in output messages', function () {
    config()->set('identity-bridge.url', 'https://custom.example.com');

    Http::fake([
        'https://custom.example.com/health' => Http::response([], 200),
        'https://custom.example.com/oauth/token' => Http::response(['access_token' => 'tok_xyz'], 200),
    ]);

    $this->artisan('identity-bridge:check')
        ->expectsOutputToContain('https://custom.example.com')
        ->assertExitCode(0);
});
