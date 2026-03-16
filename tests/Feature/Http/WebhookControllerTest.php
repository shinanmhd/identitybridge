<?php

use IgniteLabs\IdentityBridge\Events\GhostCreated;
use IgniteLabs\IdentityBridge\Events\KeyRotated;
use IgniteLabs\IdentityBridge\Events\TokenRevoked;
use IgniteLabs\IdentityBridge\Events\UserDeleted;
use IgniteLabs\IdentityBridge\Events\UserIdentityMerged;
use IgniteLabs\IdentityBridge\Events\UserKycUpdated;
use IgniteLabs\IdentityBridge\Events\UserPhoneUpdated;
use IgniteLabs\IdentityBridge\Events\UserRegistered;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Testing\TestResponse;

// Helper: POST a signed webhook to the registered route
function webhookCall(string $event, array $payload): TestResponse
{
    $body = json_encode(['event' => $event, 'payload' => $payload]);
    $secret = config('identity-bridge.webhook_secret');
    $sig = 'sha256='.hash_hmac('sha256', $body, hash('sha256', $secret));

    return test()->call(
        'POST',
        '/webhooks/identity',
        [], [], [],
        [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_X_IDENTITY_SIGNATURE' => $sig,
        ],
        $body,
    );
}

it('user.registered fires UserRegistered with correct identity_id', function () {
    Event::fake();

    webhookCall('user.registered', ['identity_id' => 'user-abc'])
        ->assertJson(['ok' => true]);

    Event::assertDispatched(UserRegistered::class, function ($e) {
        return $e->identity_id === 'user-abc';
    });
});

it('user.registered with ghost_identity_id populates it on event', function () {
    Event::fake();

    webhookCall('user.registered', [
        'identity_id' => 'user-abc',
        'ghost_identity_id' => 'ghost-xyz',
    ])->assertJson(['ok' => true]);

    Event::assertDispatched(UserRegistered::class, function ($e) {
        return $e->ghost_identity_id === 'ghost-xyz';
    });
});

it('user.kyc_updated fires UserKycUpdated with correct kyc_tier', function () {
    Event::fake();

    webhookCall('user.kyc_updated', [
        'identity_id' => 'user-1',
        'kyc_tier' => 2,
        'is_of_legal_age' => true,
        'verified_at' => '2024-01-01T00:00:00Z',
        'revoked_at' => null,
    ])->assertJson(['ok' => true]);

    Event::assertDispatched(UserKycUpdated::class, function ($e) {
        return $e->kyc_tier === 2 && $e->identity_id === 'user-1';
    });
});

it('user.phone_updated fires UserPhoneUpdated', function () {
    Event::fake();

    webhookCall('user.phone_updated', [
        'identity_id' => 'user-1',
        'previous_phone_hash' => 'old-hash',
        'updated_at' => '2024-06-01T00:00:00Z',
    ])->assertJson(['ok' => true]);

    Event::assertDispatched(UserPhoneUpdated::class, function ($e) {
        return $e->identity_id === 'user-1' && $e->previous_phone_hash === 'old-hash';
    });
});

it('user.deleted fires UserDeleted', function () {
    Event::fake();

    webhookCall('user.deleted', [
        'identity_id' => 'user-del',
        'deleted_at' => '2024-06-01T00:00:00Z',
    ])->assertJson(['ok' => true]);

    Event::assertDispatched(UserDeleted::class, function ($e) {
        return $e->identity_id === 'user-del';
    });
});

it('ghost.created fires GhostCreated', function () {
    Event::fake();

    webhookCall('ghost.created', [
        'ghost_id' => 'ghost-1',
        'phone_hash' => 'hash-abc',
        'source' => 'sms',
        'created_at' => '2024-06-01T00:00:00Z',
    ])->assertJson(['ok' => true]);

    Event::assertDispatched(GhostCreated::class, function ($e) {
        return $e->ghost_id === 'ghost-1' && $e->source === 'sms';
    });
});

it('user.identity_merged fires UserIdentityMerged', function () {
    Event::fake();

    webhookCall('user.identity_merged', [
        'identity_id' => 'user-1',
        'ghost_id' => 'ghost-1',
        'phone_hash' => 'hash-abc',
        'merged_at' => '2024-06-01T00:00:00Z',
    ])->assertJson(['ok' => true]);

    Event::assertDispatched(UserIdentityMerged::class, function ($e) {
        return $e->identity_id === 'user-1' && $e->ghost_id === 'ghost-1';
    });
});

it('token.revoked fires TokenRevoked and writes to revocation cache', function () {
    Event::fake();

    webhookCall('token.revoked', [
        'jti' => 'token-jti-123',
        'identity_id' => 'user-1',
        'revoked_at' => '2024-06-01T00:00:00Z',
    ])->assertJson(['ok' => true]);

    Event::assertDispatched(TokenRevoked::class);

    $cacheKey = config('identity-bridge.cache_prefix').'revoked:token-jti-123';
    expect(Cache::get($cacheKey))->toBeTrue();
});

it('key.rotated fires KeyRotated with new_kid', function () {
    Event::fake();

    webhookCall('key.rotated', [
        'new_kid' => 'kid-2025',
        'transition_window_hours' => 24,
    ])->assertJson(['ok' => true]);

    Event::assertDispatched(KeyRotated::class, function ($e) {
        return $e->new_kid === 'kid-2025' && $e->transition_window_hours === 24;
    });
});

it('unknown event returns 422', function () {
    webhookCall('unknown.event', [])->assertStatus(422);
});

it('rejects missing event field with 422', function () {
    $body = json_encode(['payload' => ['identity_id' => 'x']]);
    $secret = config('identity-bridge.webhook_secret');
    $sig = 'sha256='.hash_hmac('sha256', $body, hash('sha256', $secret));

    test()->call('POST', '/webhooks/identity', [], [], [],
        ['CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json', 'HTTP_X_IDENTITY_SIGNATURE' => $sig],
        $body,
    )->assertStatus(422);
});

it('rejects missing payload field with 422', function () {
    $body = json_encode(['event' => 'user.registered']);
    $secret = config('identity-bridge.webhook_secret');
    $sig = 'sha256='.hash_hmac('sha256', $body, hash('sha256', $secret));

    test()->call('POST', '/webhooks/identity', [], [], [],
        ['CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json', 'HTTP_X_IDENTITY_SIGNATURE' => $sig],
        $body,
    )->assertStatus(422);
});

it('deduplicates webhook delivery — second call with same jti returns 200 without re-firing event', function () {
    Event::fake();

    $payload = ['identity_id' => 'user-dup', 'jti' => 'unique-webhook-jti-123'];

    webhookCall('user.registered', $payload)->assertStatus(200)->assertJson(['ok' => true]);
    webhookCall('user.registered', $payload)->assertStatus(200)->assertJson(['ok' => true]);

    // Event should only fire once despite two webhook deliveries
    Event::assertDispatchedTimes(UserRegistered::class, 1);
});

it('rejects webhook with timestamp older than 5 minutes', function () {
    Event::fake();

    $stalePayload = [
        'identity_id' => 'user-stale',
        'timestamp' => time() - 400, // 400 seconds ago — beyond 300s window
    ];

    webhookCall('user.registered', $stalePayload)->assertStatus(422);
    Event::assertNotDispatched(UserRegistered::class);
});

it('accepts webhook with timestamp within 5 minutes', function () {
    Event::fake();

    $freshPayload = [
        'identity_id' => 'user-fresh',
        'timestamp' => time() - 60, // 60 seconds ago — within window
    ];

    webhookCall('user.registered', $freshPayload)->assertStatus(200);
    Event::assertDispatched(UserRegistered::class);
});

it('missing signature returns 401', function () {
    $body = json_encode(['event' => 'user.registered', 'payload' => ['identity_id' => 'x']]);

    $response = test()->call(
        'POST',
        '/webhooks/identity',
        [], [], [],
        ['CONTENT_TYPE' => 'application/json', 'HTTP_ACCEPT' => 'application/json'],
        $body,
    );

    $response->assertStatus(401);
});

it('valid signature passes middleware and fires event', function () {
    Event::fake();

    $payload = ['identity_id' => 'user-sig-test', 'ghost_identity_id' => null];
    $body = json_encode(['event' => 'user.registered', 'payload' => $payload]);
    $secret = config('identity-bridge.webhook_secret');
    $sig = 'sha256='.hash_hmac('sha256', $body, hash('sha256', $secret));

    $response = test()->call(
        'POST',
        '/webhooks/identity',
        [], [], [],
        [
            'CONTENT_TYPE' => 'application/json',
            'HTTP_ACCEPT' => 'application/json',
            'HTTP_X_IDENTITY_SIGNATURE' => $sig,
        ],
        $body,
    );

    $response->assertStatus(200)->assertJson(['ok' => true]);
    Event::assertDispatched(UserRegistered::class, fn ($e) => $e->identity_id === 'user-sig-test');
});
