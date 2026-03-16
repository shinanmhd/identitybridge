<?php

use IgniteLabs\IdentityBridge\Http\Middleware\RequireKycTier;
use IgniteLabs\IdentityBridge\Identity\IdentityClaims;
use IgniteLabs\IdentityBridge\Tests\Fixtures\KeyFixture;
use Illuminate\Http\Request;

function claimsWithTier(int $tier): IdentityClaims
{
    return new IdentityClaims(KeyFixture::makeClaims(['kyc_tier' => $tier]));
}

function requestWithClaims(IdentityClaims $claims): Request
{
    $request = Request::create('/test', 'GET');
    $request->attributes->set('identity_claims', $claims);

    return $request;
}

it('missing claims returns 401', function () {
    $request = Request::create('/test', 'GET');
    $middleware = new RequireKycTier;
    $response = $middleware->handle($request, fn ($r) => response('ok'), 1);

    expect($response->getStatusCode())->toBe(401)
        ->and($response->getData(true)['error'])->toBe('Unauthorized');
});

it('tier 0 allows all requests regardless of kyc_tier', function () {
    $request = requestWithClaims(claimsWithTier(0));
    $middleware = new RequireKycTier;
    $response = $middleware->handle($request, fn ($r) => response('ok'), 0);

    expect($response->getStatusCode())->toBe(200);
});

it('tier 1 blocks kyc_tier=0', function () {
    $request = requestWithClaims(claimsWithTier(0));
    $middleware = new RequireKycTier;
    $response = $middleware->handle($request, fn ($r) => response('ok'), 1);

    expect($response->getStatusCode())->toBe(403);
});

it('tier 2 blocks kyc_tier=1', function () {
    $request = requestWithClaims(claimsWithTier(1));
    $middleware = new RequireKycTier;
    $response = $middleware->handle($request, fn ($r) => response('ok'), 2);

    expect($response->getStatusCode())->toBe(403);
});

it('tier 2 allows kyc_tier=2', function () {
    $request = requestWithClaims(claimsWithTier(2));
    $middleware = new RequireKycTier;
    $response = $middleware->handle($request, fn ($r) => response('ok'), 2);

    expect($response->getStatusCode())->toBe(200);
});

it('tier 2 allows kyc_tier=3 (higher tier satisfies requirement)', function () {
    $request = requestWithClaims(claimsWithTier(3));
    $middleware = new RequireKycTier;
    $response = $middleware->handle($request, fn ($r) => response('ok'), 2);

    expect($response->getStatusCode())->toBe(200);
});

it('403 response contains verify_url from config', function () {
    $request = requestWithClaims(claimsWithTier(0));
    $middleware = new RequireKycTier;
    $response = $middleware->handle($request, fn ($r) => response('ok'), 2);

    $data = $response->getData(true);
    expect($response->getStatusCode())->toBe(403)
        ->and($data['error'])->toBe('KYC verification required')
        ->and($data['required_tier'])->toBe(2)
        ->and($data['verify_url'])->toBe(config('identity-bridge.kyc_url'));
});
