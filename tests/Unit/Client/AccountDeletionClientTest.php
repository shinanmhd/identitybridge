<?php

use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Dto\AccountDeletionProof;
use IgniteLabs\IdentityBridge\Exceptions\IdentityBridgeException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    config([
        'identity-bridge.url' => 'https://identity.example',
        'identity-bridge.client_id' => 'hadhiya',
        'identity-bridge.client_secret' => 'service-secret',
        'identity-bridge.http.timeout' => 5,
        'identity-bridge.http.retries' => 1,
    ]);
});

it('requests and confirms an account deletion otp without sending caller supplied identity data', function () {
    Http::fake([
        '*/api/identity/me/account-deletion/otp' => Http::response([
            'challenge_id' => '018f47d2-d7a4-7d91-b34d-90f81fbf4a1e',
            'expires_at' => '2026-09-05T12:10:00+05:00',
            'attempts_remaining' => 5,
            'expires_in' => 600,
        ], 201),
        '*/api/identity/me/account-deletion/otp/confirm' => Http::response([
            'access_token' => 'fresh-access-token',
            'refresh_token' => 'fresh-refresh-token',
            'expires_in' => 900,
        ]),
    ]);

    $client = app(IdentityBridgeClient::class);
    $challenge = $client->requestAccountDeletionOtp('user-token', [
        'traceparent' => '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
        'Authorization' => 'attacker-controlled',
    ]);
    $proof = $client->confirmAccountDeletionOtp(
        'user-token',
        $challenge['challenge_id'],
        '123456',
        ['tracestate' => 'vendor=value'],
    );

    expect($proof)->toBeInstanceOf(AccountDeletionProof::class)
        ->and($proof->accessToken)->toBe('fresh-access-token')
        ->and($proof->refreshToken)->toBe('fresh-refresh-token')
        ->and($proof->expiresIn)->toBe(900);

    Http::assertSent(function (Request $request): bool {
        if (! str_ends_with($request->url(), '/account-deletion/otp')) {
            return true;
        }

        return $request->data() === []
            && $request->hasHeader('Authorization', 'Bearer user-token')
            && $request->hasHeader('traceparent')
            && ! $request->hasHeader('tracestate');
    });
    Http::assertSent(fn (Request $request): bool => ! str_ends_with($request->url(), '/otp/confirm')
        || ($request->data() === ['challenge_id' => $challenge['challenge_id'], 'code' => '123456']
            && $request->hasHeader('Authorization', 'Bearer user-token')
            && $request->hasHeader('tracestate', 'vendor=value')));
});

it('revokes all identity sessions with scoped service credentials and trace context', function () {
    Http::fake(['*/api/service/users/*/sessions/revoke-all' => Http::response([
        'identity_id' => 'identity-1',
        'revoked_sessions' => 3,
    ])]);

    $result = app(IdentityBridgeClient::class)->revokeAllSessions('identity-1', [
        'traceparent' => '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
        'X-Identity-Client-Secret' => 'caller-secret',
    ]);

    expect($result)->toBe(['identity_id' => 'identity-1', 'revoked_sessions' => 3]);
    Http::assertSent(fn (Request $request): bool => $request->hasHeader('X-Identity-Client-ID', 'hadhiya')
        && $request->hasHeader('X-Identity-Client-Secret', 'service-secret')
        && $request->hasHeader('traceparent')
        && $request->data() === []);
});

it('erases an identity with actor and idempotency key in their exact contract locations', function () {
    Http::fake(['*/api/service/users/*/erase' => Http::response([
        'identity_id' => 'identity-1',
        'erased' => true,
        'already_erased' => false,
        'erased_at' => '2026-09-05T12:00:00+05:00',
    ])]);

    $result = app(IdentityBridgeClient::class)->eraseIdentity(
        'identity-1',
        'admin-1',
        '018f47d2-d7a4-7d91-b34d-90f81fbf4a1e',
        ['tracestate' => 'vendor=value'],
    );

    expect($result['erased'])->toBeTrue();
    Http::assertSent(fn (Request $request): bool => $request->data() === ['admin_id' => 'admin-1']
        && $request->hasHeader('Idempotency-Key', '018f47d2-d7a4-7d91-b34d-90f81fbf4a1e')
        && $request->hasHeader('tracestate', 'vendor=value'));
});

it('maps account deletion failures to a generic typed exception without leaking response fields', function () {
    Http::fake(['*/api/service/users/*/erase' => Http::response([
        'error' => 'idempotency_conflict',
        'access_token' => 'must-not-leak',
    ], 409)]);

    expect(fn () => app(IdentityBridgeClient::class)->eraseIdentity(
        'identity-1',
        'admin-1',
        '018f47d2-d7a4-7d91-b34d-90f81fbf4a1e',
    ))->toThrow(IdentityBridgeException::class, 'idempotency_conflict');
});
