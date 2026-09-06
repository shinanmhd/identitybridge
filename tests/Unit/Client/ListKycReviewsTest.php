<?php

use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Dto\KycReviewItem;
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

it('sends optional review filters and preserves pagination metadata', function () {
    $meta = [
        'current_page' => 2,
        'last_page' => 4,
        'per_page' => 25,
        'total' => 83,
    ];

    Http::fake([
        '*/api/service/kyc/reviews*' => Http::response([
            'data' => [listKycReviewFixture()],
            'meta' => $meta,
        ]),
    ]);

    $page = app(IdentityBridgeClient::class)->listKycReviews(
        status: 'pending',
        page: 2,
        perPage: 25,
        search: 'Amina',
        claimState: 'unclaimed',
        sort: 'submitted_at',
        direction: 'asc',
    );

    expect($page['data'][0])->toBeInstanceOf(KycReviewItem::class)
        ->and($page['meta'])->toBe($meta);

    Http::assertSent(function (Request $request): bool {
        parse_str((string) parse_url($request->url(), PHP_URL_QUERY), $query);

        return $query === [
            'status' => 'pending',
            'page' => '2',
            'per_page' => '25',
            'search' => 'Amina',
            'claim_state' => 'unclaimed',
            'sort' => 'submitted_at',
            'direction' => 'asc',
        ];
    });
});

it('omits optional review filters when they are not provided', function () {
    Http::fake([
        '*/api/service/kyc/reviews' => Http::response(['data' => [], 'meta' => ['current_page' => 1]]),
    ]);

    $page = app(IdentityBridgeClient::class)->listKycReviews();

    expect($page['data'])->toBe([])
        ->and($page['meta'])->toBe(['current_page' => 1]);

    Http::assertSent(fn (Request $request): bool => $request->url() === 'https://identity.example/api/service/kyc/reviews');
});

it('rejects invalid review list inputs before sending a request', function (array $arguments) {
    Http::fake();

    expect(fn () => app(IdentityBridgeClient::class)->listKycReviews(...$arguments))
        ->toThrow(InvalidArgumentException::class);

    Http::assertNothingSent();
})->with([
    'unknown status' => [['status' => 'processing']],
    'page below one' => [['page' => 0]],
    'page size below one' => [['perPage' => 0]],
    'page size above limit' => [['perPage' => 101]],
    'blank search' => [['search' => '   ']],
    'search above limit' => [['search' => str_repeat('a', 101)]],
    'unknown claim state' => [['claimState' => 'other']],
    'unknown sort' => [['sort' => 'document_number']],
    'unknown direction' => [['direction' => 'sideways']],
]);

function listKycReviewFixture(): array
{
    return [
        'id' => 'sub-1',
        'submission_version' => 1,
        'record_version' => 3,
        'status' => 'pending',
        'draft_step' => 4,
        'full_name' => 'Amina Ahmed',
        'date_of_birth' => '1990-01-01',
        'nationality' => 'MV',
        'id_type' => 'national_id',
        'visa_applicable' => false,
        'evidence' => [],
        'consent_policy_version' => '2026-01',
        'submitted_at' => '2026-08-22T08:00:00Z',
        'identity_id' => 'identity-1',
        'masked_document' => '****3456',
        'reviewer_actor_id' => null,
        'reviewer_service_id' => null,
    ];
}
