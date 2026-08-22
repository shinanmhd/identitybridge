<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Client;

use IgniteLabs\IdentityBridge\Dto\KycReviewItem;
use IgniteLabs\IdentityBridge\Dto\KycSubmission;
use IgniteLabs\IdentityBridge\Dto\Profile;
use IgniteLabs\IdentityBridge\Exceptions\IdentityBridgeException;
use IgniteLabs\IdentityBridge\Exceptions\KycConflictException;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;

class IdentityBridgeClient
{
    public function __construct(
        private readonly Factory $http,
    ) {}

    public function getServiceToken(): string
    {
        $key = config('identity-bridge.cache_prefix', 'ib_sdk_').'service_token';

        if ($token = Cache::get($key)) {
            return $token;
        }

        $response = $this->http->post(
            config('identity-bridge.url').'/oauth/token',
            [
                'grant_type' => 'client_credentials',
                'client_id' => config('identity-bridge.client_id'),
                'client_secret' => config('identity-bridge.client_secret'),
            ]
        );

        if ($response->failed()) {
            $message = $response->json('message')
                ?? $response->json('error')
                ?? 'Failed to obtain service token';

            throw new IdentityBridgeException($message);
        }

        $token = $response->json('access_token');
        $ttl = config('identity-bridge.service_token_ttl', 3500);

        Cache::put($key, $token, $ttl);

        return $token;
    }

    public function getIdentity(string $identityId): array
    {
        $token = $this->getServiceToken();
        $response = $this->http
            ->withToken($token)
            ->get(config('identity-bridge.url')."/api/identities/{$identityId}");

        if ($response->status() === 404) {
            throw new IdentityBridgeException('Identity not found');
        }

        if ($response->failed()) {
            $message = $response->json('message')
                ?? $response->json('error')
                ?? 'Failed to fetch identity';

            throw new IdentityBridgeException($message);
        }

        return $response->json();
    }

    public function revokeToken(string $jti): bool
    {
        $token = $this->getServiceToken();
        $response = $this->http
            ->withToken($token)
            ->post(config('identity-bridge.url')."/api/tokens/{$jti}/revoke");

        if ($response->failed()) {
            $message = $response->json('message')
                ?? $response->json('error')
                ?? 'Failed to revoke token';

            throw new IdentityBridgeException($message);
        }

        return true;
    }

    public function refreshServiceToken(): string
    {
        $key = config('identity-bridge.cache_prefix', 'ib_sdk_').'service_token';
        Cache::forget($key);

        return $this->getServiceToken();
    }

    /**
     * Paginated list of all identities from the server.
     * Yields one page at a time: ['data' => [...], 'meta' => [...]]
     *
     * @return iterable<array{data: array, meta: array}>
     */
    public function listUsers(?string $since = null, int $perPage = 100): iterable
    {
        $page = 1;

        do {
            $query = array_filter([
                'per_page' => $perPage,
                'page' => $page,
                'since' => $since,
            ]);

            $token = $this->getServiceToken();
            $response = $this->http
                ->withToken($token)
                ->get(config('identity-bridge.url').'/api/service/users', $query);

            if ($response->failed()) {
                $message = $response->json('message')
                    ?? $response->json('error')
                    ?? 'Failed to list users';

                throw new IdentityBridgeException($message);
            }

            $body = $response->json();
            yield $body;

            $meta = $body['meta'] ?? [];
            $page++;
        } while (($meta['current_page'] ?? 1) < ($meta['last_page'] ?? 1));
    }

    public function profile(string $accessToken): Profile
    {
        return Profile::fromArray($this->json($this->userRequest($accessToken)->get($this->url('/api/identity/me/profile'))));
    }

    public function requestProfileOtp(string $accessToken): array
    {
        return $this->json($this->userRequest($accessToken)->post($this->url('/api/identity/me/profile/otp')));
    }

    public function confirmProfileOtp(string $accessToken, string $challengeId, string $code): array
    {
        return $this->json($this->userRequest($accessToken)->post($this->url('/api/identity/me/profile/otp/confirm'), [
            'challenge_id' => $challengeId,
            'code' => $code,
        ]));
    }

    public function updateProfile(string $accessToken, string $grantToken, array $attributes): Profile
    {
        return Profile::fromArray($this->json($this->userRequest($accessToken)->patch(
            $this->url('/api/identity/me/profile'),
            ['grant_token' => $grantToken, ...$attributes],
        )));
    }

    public function authorizeAvatar(string $accessToken): array
    {
        return $this->json($this->userRequest($accessToken)->post($this->url('/api/identity/me/profile/avatar-authorizations')));
    }

    public function uploadAvatar(string $uploadUrl, string $filePath, string $fileName): array
    {
        return $this->upload($uploadUrl, $filePath, $fileName);
    }

    public function finalizeAvatar(string $accessToken, string $uploadId): Profile
    {
        return Profile::fromArray($this->json($this->userRequest($accessToken)->post(
            $this->url('/api/identity/me/profile/avatar/finalize'),
            ['upload_id' => $uploadId],
        )));
    }

    public function createKycDraft(string $accessToken): KycSubmission
    {
        return KycSubmission::fromArray($this->json($this->userRequest($accessToken)->post(
            $this->url('/api/identity/me/kyc/drafts'),
        )));
    }

    public function getKycDraft(string $accessToken, string $submissionId): KycSubmission
    {
        return KycSubmission::fromArray($this->json($this->userRequest($accessToken)->get(
            $this->url("/api/identity/me/kyc/drafts/{$submissionId}"),
        )));
    }

    public function updateKycDraft(string $accessToken, string $submissionId, array $step): KycSubmission
    {
        return KycSubmission::fromArray($this->json($this->userRequest($accessToken)->patch(
            $this->url("/api/identity/me/kyc/drafts/{$submissionId}"),
            $step,
        )));
    }

    public function authorizeKycEvidence(string $accessToken, string $submissionId, string $kind): array
    {
        return $this->json($this->userRequest($accessToken)->post(
            $this->url("/api/identity/me/kyc/drafts/{$submissionId}/evidence-authorizations"),
            ['kind' => $kind],
        ));
    }

    public function uploadKycEvidence(string $uploadUrl, string $filePath, string $fileName): array
    {
        return $this->upload($uploadUrl, $filePath, $fileName);
    }

    public function submitKycDraft(string $accessToken, string $submissionId, string $idempotencyKey): KycSubmission
    {
        return KycSubmission::fromArray($this->json($this->userRequest($accessToken)->post(
            $this->url("/api/identity/me/kyc/drafts/{$submissionId}/submit"),
            ['idempotency_key' => $idempotencyKey],
        )));
    }

    /** @return array{data: list<KycReviewItem>, meta: array} */
    public function listKycReviews(
        ?string $status = null,
        ?int $page = null,
        ?int $perPage = null,
        ?string $search = null,
        ?string $claimState = null,
        ?string $sort = null,
        ?string $direction = null,
    ): array {
        $this->validateKycReviewListInput($status, $page, $perPage, $search, $claimState, $sort, $direction);

        $body = $this->json($this->serviceRequest()->get(
            $this->url('/api/service/kyc/reviews'),
            array_filter([
                'status' => $status,
                'page' => $page,
                'per_page' => $perPage,
                'search' => $search === null ? null : trim($search),
                'claim_state' => $claimState,
                'sort' => $sort,
                'direction' => $direction,
            ], static fn (mixed $value): bool => $value !== null),
        ));
        $body['data'] = array_map(KycReviewItem::fromArray(...), $body['data'] ?? []);

        return $body;
    }

    private function validateKycReviewListInput(
        ?string $status,
        ?int $page,
        ?int $perPage,
        ?string $search,
        ?string $claimState,
        ?string $sort,
        ?string $direction,
    ): void {
        if ($status !== null && ! in_array($status, ['pending', 'verified', 'rejected'], true)) {
            throw new \InvalidArgumentException('Invalid KYC review status.');
        }

        if ($page !== null && $page < 1) {
            throw new \InvalidArgumentException('KYC review page must be at least 1.');
        }

        if ($perPage !== null && ($perPage < 1 || $perPage > 100)) {
            throw new \InvalidArgumentException('KYC review page size must be between 1 and 100.');
        }

        if ($search !== null && trim($search) === '') {
            throw new \InvalidArgumentException('KYC review search must not be blank.');
        }

        if ($search !== null && mb_strlen(trim($search)) > 100) {
            throw new \InvalidArgumentException('KYC review search must not exceed 100 characters.');
        }

        if ($claimState !== null && ! in_array($claimState, ['claimed', 'unclaimed'], true)) {
            throw new \InvalidArgumentException('Invalid KYC review claim state.');
        }

        if ($sort !== null && ! in_array($sort, ['submitted_at', 'full_name', 'status', 'record_version'], true)) {
            throw new \InvalidArgumentException('Invalid KYC review sort field.');
        }

        if ($direction !== null && ! in_array($direction, ['asc', 'desc'], true)) {
            throw new \InvalidArgumentException('Invalid KYC review sort direction.');
        }
    }

    public function getKycReview(string $submissionId): KycReviewItem
    {
        return KycReviewItem::fromArray($this->json($this->serviceRequest()->get(
            $this->url("/api/service/kyc/reviews/{$submissionId}"),
        )));
    }

    public function claimKycReview(string $submissionId, string $actorId, int $expectedVersion): KycReviewItem
    {
        return $this->reviewCommand($submissionId, 'claim', [
            'reviewer_actor_id' => $actorId,
            'expected_version' => $expectedVersion,
        ]);
    }

    public function releaseKycReview(string $submissionId, string $actorId, int $expectedVersion): KycReviewItem
    {
        return $this->reviewCommand($submissionId, 'release', [
            'reviewer_actor_id' => $actorId,
            'expected_version' => $expectedVersion,
        ]);
    }

    public function authorizeKycEvidenceView(string $submissionId, string $evidenceId, string $actorId): array
    {
        return $this->json($this->serviceRequest()->post(
            $this->url("/api/service/kyc/reviews/{$submissionId}/evidence/{$evidenceId}/authorization"),
            ['reviewer_actor_id' => $actorId],
        ));
    }

    public function approveKycReview(
        string $submissionId,
        string $actorId,
        int $expectedVersion,
        string $idempotencyKey,
        array $checklist,
    ): KycReviewItem {
        return $this->reviewCommand($submissionId, 'approve', [
            'reviewer_actor_id' => $actorId,
            'expected_version' => $expectedVersion,
            'idempotency_key' => $idempotencyKey,
            'checklist' => $checklist,
        ]);
    }

    public function rejectKycReview(
        string $submissionId,
        string $actorId,
        int $expectedVersion,
        string $idempotencyKey,
        string $note,
    ): KycReviewItem {
        return $this->reviewCommand($submissionId, 'reject', [
            'reviewer_actor_id' => $actorId,
            'expected_version' => $expectedVersion,
            'idempotency_key' => $idempotencyKey,
            'note' => $note,
        ]);
    }

    private function reviewCommand(string $submissionId, string $command, array $payload): KycReviewItem
    {
        return KycReviewItem::fromArray($this->json($this->serviceRequest()->post(
            $this->url("/api/service/kyc/reviews/{$submissionId}/{$command}"),
            $payload,
        )));
    }

    private function userRequest(string $accessToken): PendingRequest
    {
        return $this->request()->withToken($accessToken);
    }

    private function serviceRequest(): PendingRequest
    {
        return $this->request()->withHeaders([
            'X-Identity-Client-ID' => (string) config('identity-bridge.client_id'),
            'X-Identity-Client-Secret' => (string) config('identity-bridge.client_secret'),
        ]);
    }

    private function request(): PendingRequest
    {
        return $this->http
            ->acceptJson()
            ->timeout((int) config('identity-bridge.http.timeout', 5))
            ->connectTimeout((int) config('identity-bridge.http.connect_timeout', 2))
            ->retry((int) config('identity-bridge.http.retries', 1), 100, throw: false);
    }

    private function uploadRequest(): PendingRequest
    {
        $timeout = max(5, min(120, (int) config('identity-bridge.http.upload_timeout', 30)));

        return $this->request()->timeout($timeout);
    }

    private function upload(string $uploadUrl, string $filePath, string $fileName): array
    {
        try {
            return $this->json($this->uploadRequest()
                ->attach('file', fopen($filePath, 'rb'), $fileName)
                ->post($uploadUrl));
        } catch (ConnectionException) {
            throw new IdentityBridgeException('Identity Bridge upload failed.');
        }
    }

    private function json(Response $response): array
    {
        if ($response->status() === 409) {
            throw new KycConflictException((string) ($response->json('message') ?? 'KYC submission changed.'));
        }

        if ($response->failed()) {
            throw new IdentityBridgeException((string) ($response->json('message') ?? $response->json('error') ?? 'Identity Bridge request failed.'));
        }

        return $response->json() ?? [];
    }

    private function url(string $path): string
    {
        return rtrim((string) (config('identity-bridge.internal_url') ?: config('identity-bridge.url')), '/').$path;
    }
}
