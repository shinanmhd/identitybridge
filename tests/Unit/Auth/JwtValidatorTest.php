<?php

use IgniteLabs\IdentityBridge\Auth\JwksProvider;
use IgniteLabs\IdentityBridge\Auth\JwtValidator;
use IgniteLabs\IdentityBridge\Identity\IdentityClaims;
use IgniteLabs\IdentityBridge\Tests\Fixtures\KeyFixture;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    $this->key  = KeyFixture::generate('test-key-1');
    $this->jwks = KeyFixture::makeJwks($this->key['public'], $this->key['kid']);
    Http::fake(['*' => Http::response($this->jwks, 200)]);
    Cache::flush();
    config(['identity-bridge.issuer'       => 'https://identity.ignitlabs.mv']);
    config(['identity-bridge.audience'     => 'test-app']);
    config(['identity-bridge.jwt_leeway'   => 30]);
    config(['identity-bridge.cache_prefix' => 'ib_sdk_']);
});

it('returns IdentityClaims for a valid token', function () {
    $claims = KeyFixture::makeClaims();
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    $result = app(JwtValidator::class)->validate($token);

    expect($result)->toBeInstanceOf(IdentityClaims::class)
        ->and($result->sub())->toBe($claims['sub']);
});

it('returns null for expired token', function () {
    $claims = KeyFixture::makeClaims(['exp' => time() - 1000]);
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    expect(app(JwtValidator::class)->validate($token))->toBeNull();
});

it('returns null for wrong issuer', function () {
    $claims = KeyFixture::makeClaims(['iss' => 'https://evil.example.com']);
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    expect(app(JwtValidator::class)->validate($token))->toBeNull();
});

it('returns null for wrong audience', function () {
    $claims = KeyFixture::makeClaims(['aud' => ['other-app']]);
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    expect(app(JwtValidator::class)->validate($token))->toBeNull();
});

it('returns null for bad signature', function () {
    $otherKey = KeyFixture::generate('other-key');
    $claims   = KeyFixture::makeClaims();
    $token    = KeyFixture::makeJwt($claims, $otherKey['private'], $this->key['kid']);

    expect(app(JwtValidator::class)->validate($token))->toBeNull();
});

it('returns null for unknown kid', function () {
    $claims = KeyFixture::makeClaims();
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], 'unknown-key-id');

    expect(app(JwtValidator::class)->validate($token))->toBeNull();
});

it('returns null for token in revocation mirror', function () {
    $jti    = 'revoked-jti-' . uniqid();
    $claims = KeyFixture::makeClaims(['jti' => $jti]);
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    Cache::put('ib_sdk_revoked:' . $jti, true, 900);

    expect(app(JwtValidator::class)->validate($token))->toBeNull();
});

it('returns null for malformed token string', function () {
    expect(app(JwtValidator::class)->validate('not.a.valid.jwt'))->toBeNull();
    expect(app(JwtValidator::class)->validate('onlyone'))->toBeNull();
    expect(app(JwtValidator::class)->validate(''))->toBeNull();
});

it('returns valid claims for token within leeway window (exp = now - 25s)', function () {
    $claims = KeyFixture::makeClaims(['exp' => time() - 25]); // within 30s leeway
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    expect(app(JwtValidator::class)->validate($token))->toBeInstanceOf(IdentityClaims::class);
});

it('returns null for token just outside leeway window (exp = now - 35s)', function () {
    $claims = KeyFixture::makeClaims(['exp' => time() - 35]); // outside 30s leeway
    $token  = KeyFixture::makeJwt($claims, $this->key['private'], $this->key['kid']);

    expect(app(JwtValidator::class)->validate($token))->toBeNull();
});

it('checks revocation mirror before verifying signature (revoked JTI fails fast)', function () {
    $jti = 'fast-revoked-' . uniqid();

    // Put JTI in mirror — use a DIFFERENT key to sign so signature would fail anyway
    Cache::put('ib_sdk_revoked:' . $jti, true, 900);

    $otherKey = KeyFixture::generate('other');
    $claims   = KeyFixture::makeClaims(['jti' => $jti]);
    $token    = KeyFixture::makeJwt($claims, $otherKey['private'], $this->key['kid']);

    // Should return null immediately from revocation check (step 2), not from sig check
    expect(app(JwtValidator::class)->validate($token))->toBeNull();
    Http::assertNothingSent(); // No JWKS fetch since we short-circuited
});
