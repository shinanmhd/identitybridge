<?php

use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Dto\KycReviewItem;
use IgniteLabs\IdentityBridge\Dto\KycSubmission;
use IgniteLabs\IdentityBridge\Dto\Profile;
use IgniteLabs\IdentityBridge\Exceptions\KycConflictException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    config([
        'identity-bridge.url' => 'https://identity.example',
        'identity-bridge.client_id' => 'hadhiya',
        'identity-bridge.client_secret' => 'secret',
        'identity-bridge.http.timeout' => 5,
        'identity-bridge.http.retries' => 1,
    ]);
});

it('maps the authoritative profile and OTP mutation contract', function () {
    Http::fake([
        '*/api/identity/me/profile' => Http::sequence()
            ->push(profileFixture(), 200)
            ->push([...profileFixture(), 'name' => 'New Name', 'profile_version' => 8], 200),
        '*/api/identity/me/profile/otp' => Http::response(['challenge_id' => 'otp-1', 'expires_in' => 300]),
        '*/api/identity/me/profile/otp/confirm' => Http::response(['grant_token' => 'grant-1', 'expires_in' => 300]),
    ]);

    $client = app(IdentityBridgeClient::class);

    expect($client->profile('user-token'))->toBeInstanceOf(Profile::class)
        ->and($client->requestProfileOtp('user-token'))->toBe(['challenge_id' => 'otp-1', 'expires_in' => 300])
        ->and($client->confirmProfileOtp('user-token', 'otp-1', '123456'))->toBe(['grant_token' => 'grant-1', 'expires_in' => 300])
        ->and($client->updateProfile('user-token', 'grant-1', ['name' => 'New Name'])->profileVersion)->toBe(8);

    Http::assertSent(fn (Request $request) => $request->hasHeader('Authorization', 'Bearer user-token'));
});

it('maps drafts and submits with an idempotency key', function () {
    Http::fake([
        '*/api/identity/me/kyc/drafts' => Http::response(kycFixture(), 201),
        '*/api/identity/me/kyc/drafts/sub-1' => Http::response([...kycFixture(), 'draft_step' => 3, 'status' => 'rejected', 'rejection_note' => 'Please upload a clearer image.'], 200),
        '*/api/identity/me/kyc/drafts/sub-1/submit' => Http::response([...kycFixture(), 'status' => 'pending'], 200),
        '*/api/identity/me/kyc/drafts/sub-1/evidence-authorizations' => Http::response([
            'upload_id' => 'upload-1', 'upload_url' => 'https://identity.example/upload', 'expires_at' => '2026-08-22T12:00:00Z',
        ], 201),
    ]);

    $client = app(IdentityBridgeClient::class);

    expect($client->createKycDraft('user-token'))->toBeInstanceOf(KycSubmission::class)
        ->and($client->updateKycDraft('user-token', 'sub-1', ['step' => 2, 'full_name' => 'Test User'])->rejectionNote)->toBe('Please upload a clearer image.')
        ->and($client->authorizeKycEvidence('user-token', 'sub-1', 'selfie')['upload_id'])->toBe('upload-1')
        ->and($client->submitKycDraft('user-token', 'sub-1', str_repeat('i', 32))->status->value)->toBe('pending');

    Http::assertSent(fn (Request $request) => str_ends_with($request->url(), '/submit')
        && $request['idempotency_key'] === str_repeat('i', 32));
});

it('uses scoped service credentials and optimistic idempotent review commands', function () {
    Http::fake([
        '*/api/service/kyc/reviews/sub-1/claim' => Http::response([...reviewFixture(), 'record_version' => 4]),
        '*/api/service/kyc/reviews/sub-1/approve' => Http::response([...reviewFixture(), 'status' => 'verified', 'record_version' => 5]),
        '*/api/service/kyc/reviews*' => Http::response(['data' => [reviewFixture()], 'meta' => ['current_page' => 1, 'last_page' => 1]]),
    ]);

    $client = app(IdentityBridgeClient::class);
    $page = $client->listKycReviews();
    $claimed = $client->claimKycReview('sub-1', 'staff-1', 3);
    $decision = $client->approveKycReview('sub-1', 'staff-1', 4, str_repeat('a', 32), [
        'document_matches' => true,
        'selfie_matches' => true,
        'details_accurate' => true,
    ]);

    expect($page['data'][0])->toBeInstanceOf(KycReviewItem::class)
        ->and($claimed->recordVersion)->toBe(4)
        ->and($decision->status->value)->toBe('verified');

    Http::assertSent(fn (Request $request) => str_contains($request->url(), '/api/service/kyc/reviews')
        && $request->hasHeader('X-Identity-Client-ID', 'hadhiya')
        && $request->hasHeader('X-Identity-Client-Secret', 'secret'));
});

it('maps review conflicts without leaking the response body', function () {
    Http::fake(['*/api/service/kyc/reviews/sub-1/claim' => Http::response([
        'error' => 'review_conflict', 'message' => 'record version changed', 'document_number' => 'secret',
    ], 409)]);

    expect(fn () => app(IdentityBridgeClient::class)->claimKycReview('sub-1', 'staff-1', 2))
        ->toThrow(KycConflictException::class, 'record version changed');
});

function profileFixture(): array
{
    return [
        'identity_id' => 'identity-1', 'phone_number' => '9607000000', 'name' => 'Test User',
        'email' => 'test@example.com', 'avatar_url' => null, 'avatar_version' => null,
        'profile_version' => 7, 'kyc_tier' => 1, 'kyc_status' => 'draft',
    ];
}

function kycFixture(): array
{
    return [
        'id' => 'sub-1', 'submission_version' => 1, 'record_version' => 2, 'status' => 'draft',
        'draft_step' => 1, 'full_name' => null, 'date_of_birth' => null, 'nationality' => null,
        'id_type' => null, 'visa_applicable' => false, 'evidence' => [],
        'consent_policy_version' => null, 'submitted_at' => null,
    ];
}

function reviewFixture(): array
{
    return [
        ...kycFixture(), 'status' => 'pending', 'record_version' => 3,
        'identity_id' => 'identity-1', 'masked_document' => '****3456',
        'reviewer_actor_id' => null, 'reviewer_service_id' => null,
    ];
}
