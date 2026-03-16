<?php

use IgniteLabs\IdentityBridge\Identity\IdentityClaims;

test('identity() returns IdentityClaims when identity_claims attribute is set on request', function () {
    $claims = new IdentityClaims(['sub' => 'user-123', 'kyc_tier' => 1]);
    $this->app->make('request')->attributes->set('identity_claims', $claims);

    $result = identity();

    expect($result)->toBeInstanceOf(IdentityClaims::class);
});

test('identity() throws RuntimeException when no claims in request attributes', function () {
    expect(fn () => identity())->toThrow(\RuntimeException::class);
});

test('identity() returns the exact IdentityClaims instance stored in request', function () {
    $claims = new IdentityClaims(['sub' => 'user-456', 'kyc_tier' => 2]);
    $this->app->make('request')->attributes->set('identity_claims', $claims);

    $result = identity();

    expect($result)->toBe($claims);
});
