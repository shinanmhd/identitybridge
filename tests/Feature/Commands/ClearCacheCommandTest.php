<?php

use Illuminate\Support\Facades\Cache;

it('clears the jwks cache key', function () {
    Cache::put('ib_sdk_jwks', ['keys' => []], 3600);

    $this->artisan('identity-bridge:clear-cache')->assertExitCode(0);

    expect(Cache::has('ib_sdk_jwks'))->toBeFalse();
});

it('clears the service_token cache key', function () {
    Cache::put('ib_sdk_service_token', 'tok_abc', 3500);

    $this->artisan('identity-bridge:clear-cache')->assertExitCode(0);

    expect(Cache::has('ib_sdk_service_token'))->toBeFalse();
});

it('outputs a confirmation message after clearing the cache', function () {
    $this->artisan('identity-bridge:clear-cache')
        ->expectsOutputToContain('Identity Bridge SDK cache cleared.')
        ->assertExitCode(0);
});
