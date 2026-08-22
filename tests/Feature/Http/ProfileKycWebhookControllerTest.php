<?php

use IgniteLabs\IdentityBridge\Events\UserKycUpdated;
use IgniteLabs\IdentityBridge\Events\UserProfileUpdated;
use Illuminate\Support\Facades\Event;
use Illuminate\Testing\TestResponse;

it('keeps legacy KYC webhooks compatible', function () {
    Event::fake();

    profileKycWebhookCall('user.kyc_updated', [
        'identity_id' => 'identity-1',
        'kyc_tier' => 2,
        'is_of_legal_age' => true,
        'verified_at' => '2026-08-22T00:00:00Z',
    ])->assertOk();

    Event::assertDispatched(UserKycUpdated::class, fn (UserKycUpdated $event) => $event->identity_id === 'identity-1'
        && $event->kyc_tier === 2
        && $event->submission_id === null
        && $event->record_version === null
    );
});

it('publishes versioned approval and rejection fields without evidence data', function () {
    Event::fake();

    profileKycWebhookCall('user.kyc_updated', [
        'identity_id' => 'identity-1',
        'submission_id' => 'submission-1',
        'submission_version' => 2,
        'record_version' => 7,
        'status' => 'rejected',
        'kyc_tier' => 1,
        'is_of_legal_age' => false,
        'decision_at' => '2026-08-22T00:00:00Z',
        'verified_at' => null,
        'rejection_note' => 'Please upload a clearer document.',
    ])->assertOk();

    Event::assertDispatched(UserKycUpdated::class, fn (UserKycUpdated $event) => $event->submission_id === 'submission-1'
        && $event->submission_version === 2
        && $event->record_version === 7
        && $event->status === 'rejected'
        && $event->rejection_note === 'Please upload a clearer document.'
        && ! property_exists($event, 'evidence')
    );
});

it('publishes safe versioned profile updates once per webhook jti', function () {
    Event::fake();
    $payload = [
        'identity_id' => 'identity-1',
        'profile_version' => 4,
        'name' => 'Updated User',
        'email' => 'updated@example.com',
        'avatar_url' => 'https://identity.example/avatar',
        'avatar_version' => 3,
        'updated_at' => '2026-08-22T00:00:00Z',
        'jti' => 'profile-delivery-1',
    ];

    profileKycWebhookCall('user.profile_updated', $payload)->assertOk();
    profileKycWebhookCall('user.profile_updated', $payload)->assertOk();

    Event::assertDispatchedTimes(UserProfileUpdated::class, 1);
    Event::assertDispatched(UserProfileUpdated::class, fn (UserProfileUpdated $event) => $event->identity_id === 'identity-1'
        && $event->profile_version === 4
        && $event->name === 'Updated User'
        && $event->avatar_version === 3
    );
});

function profileKycWebhookCall(string $event, array $payload): TestResponse
{
    $body = json_encode(['event' => $event, 'payload' => $payload]);
    $signature = 'sha256='.hash_hmac('sha256', $body, hash('sha256', config('identity-bridge.webhook_secret')));

    return test()->call('POST', '/webhooks/identity', [], [], [], [
        'CONTENT_TYPE' => 'application/json',
        'HTTP_ACCEPT' => 'application/json',
        'HTTP_X_IDENTITY_SIGNATURE' => $signature,
    ], $body);
}
