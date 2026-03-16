<?php

use IgniteLabs\IdentityBridge\Auth\JwksProvider;
use IgniteLabs\IdentityBridge\Tests\Fixtures\KeyFixture;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    $this->key = KeyFixture::generate('test-key-1');
    $this->jwks = KeyFixture::makeJwks($this->key['public'], $this->key['kid']);
    config(['identity-bridge.jwks_url' => 'https://identity.ignitlabs.mv/.well-known/jwks.json']);
    config(['identity-bridge.jwks_ttl' => 3600]);
    config(['identity-bridge.cache_prefix' => 'ib_sdk_']);
});

it('fetches JWKS from URL on cache miss and caches result', function () {
    Cache::flush();
    Http::fake(['*' => Http::response($this->jwks, 200)]);

    $provider = app(JwksProvider::class);
    $keySet = $provider->getKeySet();

    expect($keySet)->toHaveKey('test-key-1');
    Http::assertSentCount(1);
});

it('returns keyset from cache on cache hit without HTTP call', function () {
    Http::fake(['*' => Http::response($this->jwks, 200)]);

    $provider = app(JwksProvider::class);
    $provider->getKeySet(); // first call — populates cache
    $provider->getKeySet(); // second call — should use cache

    Http::assertSentCount(1); // only one HTTP call
});

it('rotateCache() causes re-fetch on next getKeySet() call', function () {
    Http::fake(['*' => Http::response($this->jwks, 200)]);

    $provider = app(JwksProvider::class);
    $provider->getKeySet();  // fills cache
    $provider->rotateCache(); // clears cache
    $provider->getKeySet();  // should re-fetch

    Http::assertSentCount(2);
});

it('returns keyset indexed by kid', function () {
    Http::fake(['*' => Http::response($this->jwks, 200)]);

    $provider = app(JwksProvider::class);
    $keySet = $provider->getKeySet();

    expect($keySet)->toHaveKey('test-key-1');
});

it('handles dual-key JWKS (rotation window)', function () {
    $key2 = KeyFixture::generate('test-key-2');
    $dualJwks = [
        'keys' => array_merge(
            $this->jwks['keys'],
            KeyFixture::makeJwks($key2['public'], $key2['kid'])['keys']
        ),
    ];
    Http::fake(['*' => Http::response($dualJwks, 200)]);

    $provider = app(JwksProvider::class);
    $keySet = $provider->getKeySet();

    expect($keySet)->toHaveKey('test-key-1')
        ->and($keySet)->toHaveKey('test-key-2');
});
