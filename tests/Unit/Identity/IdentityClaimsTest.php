<?php

use IgniteLabs\IdentityBridge\Identity\IdentityClaims;

it('sub() returns the sub claim', function () {
    $claims = new IdentityClaims(['sub' => 'ib_abc123', 'jti' => 'jti1', 'exp' => time() + 900]);
    expect($claims->sub())->toBe('ib_abc123');
});

it('kycTier() returns int from kyc_tier claim', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'kyc_tier' => 2]);
    expect($claims->kycTier())->toBe(2);
});

it('kycTier() defaults to 0 when absent', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900]);
    expect($claims->kycTier())->toBe(0);
});

it('isVerified() is true when tier >= 1', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'kyc_tier' => 1]);
    expect($claims->isVerified())->toBeTrue();
});

it('isVerified() is false when tier is 0', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'kyc_tier' => 0]);
    expect($claims->isVerified())->toBeFalse();
});

it('isFullKyc() is true when tier >= 2', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'kyc_tier' => 2]);
    expect($claims->isFullKyc())->toBeTrue();
});

it('isFullKyc() is false when tier is 1', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'kyc_tier' => 1]);
    expect($claims->isFullKyc())->toBeFalse();
});

it('isAmlCleared() is true when tier >= 3', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'kyc_tier' => 3]);
    expect($claims->isAmlCleared())->toBeTrue();
});

it('isOfLegalAge() returns bool, defaults false', function () {
    $with    = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'is_of_legal_age' => true]);
    $without = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900]);
    expect($with->isOfLegalAge())->toBeTrue()
        ->and($without->isOfLegalAge())->toBeFalse();
});

it('phoneVerified() returns bool, defaults false', function () {
    $with    = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'phone_verified' => true]);
    $without = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900]);
    expect($with->phoneVerified())->toBeTrue()
        ->and($without->phoneVerified())->toBeFalse();
});

it('ghostIdentityId() returns null when absent', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900]);
    expect($claims->ghostIdentityId())->toBeNull();
});

it('ghostIdentityId() returns value when present', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'ghost_identity_id' => 'g123']);
    expect($claims->ghostIdentityId())->toBe('g123');
});

it('jti() returns the jti claim', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'my-jti', 'exp' => time() + 900]);
    expect($claims->jti())->toBe('my-jti');
});

it('expiresAt() returns a Carbon from exp timestamp', function () {
    $exp    = time() + 900;
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => $exp]);
    expect($claims->expiresAt()->timestamp)->toBe($exp);
});

it('get() returns default when key absent', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900]);
    expect($claims->get('nonexistent', 'default_val'))->toBe('default_val');
});

it('get() returns value when key present', function () {
    $claims = new IdentityClaims(['sub' => 'x', 'jti' => 'j', 'exp' => time() + 900, 'custom' => 'val']);
    expect($claims->get('custom'))->toBe('val');
});
