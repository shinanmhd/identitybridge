<?php

use Firebase\JWT\JWT;
use IgniteLabs\IdentityBridge\AdminSso\StaffClaims;
use IgniteLabs\IdentityBridge\Tests\Fixtures\KeyFixture;

it('constructs from a valid staff jwt payload', function () {
    $payload = (object) [
        'sub'         => 'admin-uuid-123',
        'identity_id' => 'admin-uuid-123',
        'name'        => 'Ali Waheed',
        'email'       => 'ali@ignitlabs.mv',
        'is_staff'    => true,
        'aud'         => 'hadhiya-fihaara',
        'iss'         => 'https://identity.ignitlabs.mv',
        'iat'         => time() - 10,
        'exp'         => time() + 3590,
        'jti'         => 'unique-jti-abc',
    ];

    $claims = StaffClaims::fromPayload($payload);

    expect($claims->sub)->toBe('admin-uuid-123')
        ->and($claims->name)->toBe('Ali Waheed')
        ->and($claims->email)->toBe('ali@ignitlabs.mv')
        ->and($claims->isStaff)->toBeTrue()
        ->and($claims->isExpired())->toBeFalse();
});

it('throws when is_staff is false', function () {
    $payload = (object) [
        'sub'         => 'user-uuid',
        'identity_id' => 'user-uuid',
        'name'        => 'Regular User',
        'email'       => 'user@example.com',
        'is_staff'    => false,
        'aud'         => 'app',
        'iss'         => 'https://identity.ignitlabs.mv',
        'iat'         => time(),
        'exp'         => time() + 3600,
        'jti'         => 'jti-xyz',
    ];

    expect(fn () => StaffClaims::fromPayload($payload))
        ->toThrow(InvalidArgumentException::class);
});

it('detects expired tokens', function () {
    $payload = (object) [
        'sub'         => 'admin-uuid',
        'identity_id' => 'admin-uuid',
        'name'        => 'Old Admin',
        'email'       => 'old@ignitlabs.mv',
        'is_staff'    => true,
        'aud'         => 'app',
        'iss'         => 'https://identity.ignitlabs.mv',
        'iat'         => time() - 7200,
        'exp'         => time() - 3600,
        'jti'         => 'jti-expired',
    ];

    $claims = StaffClaims::fromPayload($payload);
    expect($claims->isExpired())->toBeTrue();
});
