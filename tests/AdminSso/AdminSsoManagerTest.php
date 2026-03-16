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
        clientId:    'test-client-uuid',
        redirectUri: 'https://paybr.test/admin/sso/callback',
        state:       'random-state',
        challenge:   'some-challenge',
    );

    expect($url)->toContain('identity.ignitlabs.mv/oauth/authorize')
        ->and($url)->toContain('client_id=test-client-uuid')
        ->and($url)->toContain('response_type=code')
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
        clientId:    'test-client-uuid',
    );

    expect($result)->toBe($token);
});

it('AdminSsoManager builds authorization URL using identity-bridge.url config key', function () {
    config(['identity-bridge.url'       => 'http://localhost:8091']);
    config(['identity-bridge.client_id' => 'paybridgecentral-uuid']);

    $manager = app(\IgniteLabs\IdentityBridge\AdminSso\AdminSsoManager::class);

    $url = $manager->buildAuthorizationUrl(
        clientId:    'paybridgecentral-uuid',
        redirectUri: 'http://localhost:8090/admin/sso/callback',
        state:       'teststate',
        challenge:   'testchallenge',
    );

    // Must start with the configured IB Central URL and use /oauth/authorize
    expect($url)->toStartWith('http://localhost:8091')
        ->and($url)->toContain('/oauth/authorize');
});

it('config file has app_slug and admin_sso keys', function () {
    expect(config('identity-bridge'))->toHaveKey('app_slug')
        ->and(config('identity-bridge'))->toHaveKey('admin_sso');
});

it('rejects a token with HS256 algorithm header (algorithm confusion attack)', function () {
    // Attacker signs a token using the PUBLIC KEY as an HMAC secret
    $now     = time();
    $payload = json_encode([
        'sub'         => 'attacker',
        'identity_id' => 'attacker',
        'name'        => 'Attacker',
        'email'       => 'attacker@evil.com',
        'is_staff'    => true,
        'aud'         => 'paybr',
        'iss'         => 'https://identity.ignitlabs.mv',
        'iat'         => $now,
        'exp'         => $now + 3600,
        'jti'         => 'attacker-jti',
    ]);

    $header    = base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'HS256']));
    $body      = base64_encode($payload);
    $signature = base64_encode(hash_hmac('sha256', "{$header}.{$body}", $this->keys['public'], true));
    $token     = "{$header}.{$body}.{$signature}";

    expect(fn () => $this->manager->decodeToken($token))
        ->toThrow(InvalidArgumentException::class, 'Token must use RS256 algorithm');
});

it('rejects a token with alg:none header', function () {
    $now     = time();
    $header  = rtrim(base64_encode(json_encode(['typ' => 'JWT', 'alg' => 'none'])), '=');
    $body    = rtrim(base64_encode(json_encode([
        'sub'      => 'attacker',
        'is_staff' => true,
        'exp'      => $now + 3600,
    ])), '=');
    $token = "{$header}.{$body}.";

    expect(fn () => $this->manager->decodeToken($token))
        ->toThrow(InvalidArgumentException::class, 'Token must use RS256 algorithm');
});

it('rejects a malformed token that is not three dot-separated parts', function () {
    expect(fn () => $this->manager->decodeToken('not.a.valid.jwt.token'))
        ->toThrow(InvalidArgumentException::class);
});
