<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\Facades\Http;
use IgniteLabs\IdentityBridge\AdminSso\AdminSsoManager;
use IgniteLabs\IdentityBridge\AdminSso\StaffClaims;
use IgniteLabs\IdentityBridge\Tests\Fixtures\KeyFixture;

beforeEach(function () {
    $this->keys   = KeyFixture::generate();
    $this->manager = new AdminSsoManager(
        http:              app(HttpFactory::class),
        identityBridgeUrl: 'https://identity.ignitlabs.mv',
        publicKey:         $this->keys['public'],
    );
});

it('generates a valid pkce pair', function () {
    $pkce = $this->manager->generatePkce();

    expect($pkce)->toHaveKeys(['verifier', 'challenge']);

    // Verify S256 challenge matches verifier
    $expected = rtrim(strtr(base64_encode(hash('sha256', $pkce['verifier'], true)), '+/', '-_'), '=');
    expect($pkce['challenge'])->toBe($expected);
});

it('builds a correct authorization url', function () {
    $url = $this->manager->buildAuthorizationUrl(
        appSlug:    'paybr',
        redirectUri: 'https://paybr.test/admin/sso/callback',
        state:      'random-state',
        challenge:  'some-challenge',
    );

    expect($url)->toContain('identity.ignitlabs.mv/admin/sso/launch')
        ->and($url)->toContain('app=paybr')
        ->and($url)->toContain('state=random-state')
        ->and($url)->toContain('code_challenge_method=S256');
});

it('decodes a valid staff jwt', function () {
    $now = time();
    $token = JWT::encode([
        'sub'         => 'admin-uuid',
        'identity_id' => 'admin-uuid',
        'name'        => 'Test Admin',
        'email'       => 'admin@ignitlabs.mv',
        'is_staff'    => true,
        'aud'         => 'paybr',
        'iss'         => 'https://identity.ignitlabs.mv',
        'iat'         => $now,
        'exp'         => $now + 3600,
        'jti'         => 'unique-jti',
    ], $this->keys['private'], 'RS256');

    $claims = $this->manager->decodeToken($token);

    expect($claims)->toBeInstanceOf(StaffClaims::class)
        ->and($claims->email)->toBe('admin@ignitlabs.mv')
        ->and($claims->isStaff)->toBeTrue();
});

it('exchanges code for jwt via http', function () {
    $now = time();
    $token = JWT::encode([
        'sub'         => 'admin-uuid',
        'identity_id' => 'admin-uuid',
        'name'        => 'Test Admin',
        'email'       => 'admin@ignitlabs.mv',
        'is_staff'    => true,
        'aud'         => 'paybr',
        'iss'         => 'https://identity.ignitlabs.mv',
        'iat'         => $now,
        'exp'         => $now + 3600,
        'jti'         => 'jti-xyz',
    ], $this->keys['private'], 'RS256');

    Http::fake([
        'identity.ignitlabs.mv/oauth/admin/token' => Http::response(['access_token' => $token], 200),
    ]);

    $manager = new AdminSsoManager(
        http:              app(HttpFactory::class),
        identityBridgeUrl: 'https://identity.ignitlabs.mv',
        publicKey:         $this->keys['public'],
    );

    $result = $manager->exchangeCode(
        code:        'test-code',
        verifier:    str_repeat('a', 64),
        redirectUri: 'https://paybr.test/admin/sso/callback',
    );

    expect($result)->toBe($token);
});
