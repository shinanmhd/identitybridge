<?php

use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Dto\AccountDeletionProof;
use IgniteLabs\IdentityBridge\Exceptions\AccountDeletionException;
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

it('classifies retryable otp request failures without preserving arbitrary upstream fields', function () {
    Http::fake(['*/api/identity/me/account-deletion/otp' => Http::response([
        'error' => 'too_many_requests',
        'message' => 'secret upstream details',
        'retry_after' => 37,
        'otp' => 'must-not-leak',
    ], 429)]);

    try {
        app(IdentityBridgeClient::class)->requestAccountDeletionOtp('user-token');
        $this->fail('Expected account deletion exception.');
    } catch (AccountDeletionException $exception) {
        expect($exception->getMessage())->toBe('Identity Bridge account deletion request failed.')
            ->and($exception->category)->toBe('rate_limited')
            ->and($exception->codeName)->toBe('too_many_requests')
            ->and($exception->status)->toBe(429)
            ->and($exception->retryAfter)->toBe(37)
            ->and($exception->isRetryable())->toBeTrue()
            ->and(json_encode(get_object_vars($exception), JSON_THROW_ON_ERROR))
            ->not->toContain('secret upstream details', 'must-not-leak');
    }
});

it('classifies confirmation validation failures as terminal', function () {
    Http::fake(['*/api/identity/me/account-deletion/otp/confirm' => Http::response([
        'error' => 'invalid_challenge',
        'message' => 'code was 123456',
        'access_token' => 'must-not-leak',
    ], 422)]);

    try {
        app(IdentityBridgeClient::class)->confirmAccountDeletionOtp(
            'user-token',
            '018f47d2-d7a4-7d91-b34d-90f81fbf4a1e',
            '123456',
        );
        $this->fail('Expected account deletion exception.');
    } catch (AccountDeletionException $exception) {
        expect($exception->category)->toBe('validation')
            ->and($exception->codeName)->toBe('invalid_challenge')
            ->and($exception->status)->toBe(422)
            ->and($exception->retryAfter)->toBeNull()
            ->and($exception->isRetryable())->toBeFalse();
    }
});

it('qualifies a revoke-all not-found response without string matching', function () {
    Http::fake(['*/api/service/users/*/sessions/revoke-all' => Http::response([
        'error' => 'not_found',
        'message' => 'identity phone was +9600000000',
        'client_secret' => 'must-not-leak',
    ], 404)]);

    try {
        app(IdentityBridgeClient::class)->revokeAllSessions('identity-1');
        $this->fail('Expected account deletion exception.');
    } catch (AccountDeletionException $exception) {
        expect($exception->category)->toBe('not_found')
            ->and($exception->codeName)->toBe('not_found')
            ->and($exception->status)->toBe(404)
            ->and($exception->isNotFound())->toBeTrue()
            ->and($exception->isRetryable())->toBeFalse();
    }
});

it('maps erasure authentication and server failures to distinct safe categories', function (int $status, array $body, string $category, string $code, bool $retryable) {
    Http::fake(['*/api/service/users/*/erase' => Http::response($body, $status)]);

    try {
        app(IdentityBridgeClient::class)->eraseIdentity(
            'identity-1',
            'admin-1',
            '018f47d2-d7a4-7d91-b34d-90f81fbf4a1e',
        );
        $this->fail('Expected account deletion exception.');
    } catch (AccountDeletionException $exception) {
        expect($exception->category)->toBe($category)
            ->and($exception->codeName)->toBe($code)
            ->and($exception->status)->toBe($status)
            ->and($exception->isRetryable())->toBe($retryable)
            ->and($exception->getMessage())->not->toContain('malicious', 'must-not-leak');
    }
})->with([
    'authentication is terminal' => [401, ['message' => 'malicious token detail', 'refresh_token' => 'must-not-leak'], 'authentication', 'authentication_failed', false],
    'server failure is retryable' => [503, ['error' => 'not_found', 'message' => 'malicious internal detail'], 'server', 'service_unavailable', true],
]);

it('sanitizes malformed retry timing', function (mixed $retryAfter) {
    Http::fake(['*/api/identity/me/account-deletion/otp' => Http::response([
        'error' => 'too_many_attempts',
        'retry_after' => $retryAfter,
    ], 429)]);

    try {
        app(IdentityBridgeClient::class)->requestAccountDeletionOtp('user-token');
        $this->fail('Expected account deletion exception.');
    } catch (AccountDeletionException $exception) {
        expect($exception->retryAfter)->toBeNull();
    }
})->with(['negative' => -1, 'string' => '30', 'too large' => 86401]);
