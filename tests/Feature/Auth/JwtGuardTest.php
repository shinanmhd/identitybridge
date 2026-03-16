<?php

use IgniteLabs\IdentityBridge\Auth\JwksProvider;
use IgniteLabs\IdentityBridge\Auth\JwtGuard;
use IgniteLabs\IdentityBridge\Auth\JwtValidator;
use IgniteLabs\IdentityBridge\Identity\IdentityClaims;
use IgniteLabs\IdentityBridge\Tests\Fixtures\KeyFixture;
use Illuminate\Auth\GenericUser;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    $this->key  = KeyFixture::generate('test-key-1');
    $this->jwks = KeyFixture::makeJwks($this->key['public'], $this->key['kid']);
    Http::fake(['*' => Http::response($this->jwks, 200)]);
    Cache::flush();
});

function makeRequest(?string $token = null): Request
{
    $request = Request::create('/test', 'GET');
    if ($token) {
        $request->headers->set('Authorization', 'Bearer ' . $token);
    }
    return $request;
}

function makeUserProvider(mixed $user = null): UserProvider
{
    $provider = Mockery::mock(UserProvider::class);
    $provider->shouldReceive('retrieveByCredentials')->andReturn($user);
    $provider->shouldReceive('validateCredentials')->andReturn(true);
    $provider->shouldReceive('rehashPasswordIfRequired')->andReturn(null)->byDefault();
    return $provider;
}

it('returns user for valid bearer token when shadow user exists', function () {
    $claims = KeyFixture::makeClaims();
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    $user     = new GenericUser(['id' => 1, 'identity_id' => $claims['sub']]);
    $provider = makeUserProvider($user);
    $request  = makeRequest($token);

    $guard = new JwtGuard(app(JwtValidator::class), $provider, $request);

    expect($guard->user())->toBe($user);
});

it('returns null when token valid but no matching local user', function () {
    $claims = KeyFixture::makeClaims();
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    $provider = makeUserProvider(null);
    $request  = makeRequest($token);

    $guard = new JwtGuard(app(JwtValidator::class), $provider, $request);

    expect($guard->user())->toBeNull();
});

it('returns null for invalid token', function () {
    $provider = makeUserProvider(null);
    $request  = makeRequest('invalid.token.here');

    $guard = new JwtGuard(app(JwtValidator::class), $provider, $request);

    expect($guard->user())->toBeNull();
});

it('returns null when no Authorization header', function () {
    $provider = makeUserProvider(null);
    $request  = makeRequest(); // no token

    $guard = new JwtGuard(app(JwtValidator::class), $provider, $request);

    expect($guard->user())->toBeNull();
});

it('check() returns true when user resolved', function () {
    $claims = KeyFixture::makeClaims();
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    $user     = new GenericUser(['id' => 1, 'identity_id' => $claims['sub']]);
    $provider = makeUserProvider($user);
    $guard    = new JwtGuard(app(JwtValidator::class), $provider, makeRequest($token));

    expect($guard->check())->toBeTrue();
});

it('guest() returns true when no valid token', function () {
    $provider = makeUserProvider(null);
    $guard    = new JwtGuard(app(JwtValidator::class), $provider, makeRequest());

    expect($guard->guest())->toBeTrue();
});

it('attaches IdentityClaims to request attributes after valid auth', function () {
    $claims = KeyFixture::makeClaims();
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    $user     = new GenericUser(['id' => 1, 'identity_id' => $claims['sub']]);
    $provider = makeUserProvider($user);
    $request  = makeRequest($token);

    $guard = new JwtGuard(app(JwtValidator::class), $provider, $request);
    $guard->user();

    expect($request->attributes->get('identity_claims'))->toBeInstanceOf(IdentityClaims::class);
});

it('calling user() twice returns cached user without double-validate', function () {
    $claims = KeyFixture::makeClaims();
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    $user     = new GenericUser(['id' => 1, 'identity_id' => $claims['sub']]);
    $provider = Mockery::mock(UserProvider::class);
    $provider->shouldReceive('retrieveByCredentials')->once()->andReturn($user);
    $request = makeRequest($token);

    $guard = new JwtGuard(app(JwtValidator::class), $provider, $request);
    $guard->user();
    $guard->user(); // second call — should use cached value

    // Mockery will fail if retrieveByCredentials called more than once
    expect($guard->user())->toBe($user);
});
