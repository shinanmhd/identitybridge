<?php

use IgniteLabs\IdentityBridge\Events\TokenRevoked;
use Illuminate\Support\Facades\Cache;

it('instantiating TokenRevoked writes jti to cache', function () {
    new TokenRevoked('jti-test-001', 'user-1', '2024-06-01T00:00:00Z');

    $key = config('identity-bridge.cache_prefix').'revoked:jti-test-001';
    expect(Cache::get($key))->toBeTrue();
});

it('cache key uses the configured prefix', function () {
    new TokenRevoked('jti-prefix-check', 'user-2', '2024-06-01T00:00:00Z');

    $prefixedKey = 'ib_sdk_revoked:jti-prefix-check';
    $unprefixedKey = 'revoked:jti-prefix-check';

    expect(Cache::has($prefixedKey))->toBeTrue()
        ->and(Cache::has($unprefixedKey))->toBeFalse();
});

it('revocation cache entry exists within ttl window', function () {
    new TokenRevoked('jti-ttl-check', 'user-3', '2024-06-01T00:00:00Z');

    $key = config('identity-bridge.cache_prefix').'revoked:jti-ttl-check';

    // Value should exist now
    expect(Cache::has($key))->toBeTrue();
});
