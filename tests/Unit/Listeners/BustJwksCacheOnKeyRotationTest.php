<?php

declare(strict_types=1);

use IgniteLabs\IdentityBridge\Auth\JwksProvider;
use IgniteLabs\IdentityBridge\Events\KeyRotated;
use IgniteLabs\IdentityBridge\Listeners\BustJwksCacheOnKeyRotation;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;

it('busts the JWKS cache when KeyRotated is fired', function () {
    $prefix = config('identity-bridge.cache_prefix', 'ib_sdk_');
    Cache::put($prefix.'jwks', ['keys' => []], 3600);

    event(new KeyRotated('kid-2', 24));

    expect(Cache::has($prefix.'jwks'))->toBeFalse();
});

it('wires BustJwksCacheOnKeyRotation as a listener for KeyRotated', function () {
    Event::fake();

    event(new KeyRotated('kid-3', 24));

    Event::assertDispatched(KeyRotated::class);
});

it('listener calls rotateCache on JwksProvider', function () {
    $provider = Mockery::mock(JwksProvider::class);
    $provider->shouldReceive('rotateCache')->once();

    $listener = new BustJwksCacheOnKeyRotation($provider);
    $listener->handle(new KeyRotated('kid-4', 24));
});
