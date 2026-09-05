<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Client;

use DateTimeImmutable;
use IgniteLabs\IdentityBridge\Dto\AccountDeletionProof;
use IgniteLabs\IdentityBridge\Dto\KycReviewItem;
use IgniteLabs\IdentityBridge\Dto\KycSubmission;
use IgniteLabs\IdentityBridge\Dto\Profile;
use IgniteLabs\IdentityBridge\Exceptions\AccountDeletionException;
use IgniteLabs\IdentityBridge\Exceptions\IdentityBridgeException;
use IgniteLabs\IdentityBridge\Exceptions\KycConflictException;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Str;

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

    /**
     * Request an account-deletion challenge for the bearer-token subject.
     *
     * @param  array<string, string>  $traceHeaders
     * @return array{challenge_id: string, expires_at: string, attempts_remaining: int, expires_in: int}
     */
    public function requestAccountDeletionOtp(string $accessToken, array $traceHeaders = []): array
    {
        try {
            $response = $this->withTraceHeaders(
                $this->userRequest($accessToken),
                $traceHeaders,
            )->post($this->url('/api/identity/me/account-deletion/otp'));
        } catch (\Throwable) {
            throw AccountDeletionException::transportFailure();
        }

        $body = $this->accountDeletionJson($response);
        if (! $this->isUuid($body['challenge_id'] ?? null)
            || ! $this->isDateTime($body['expires_at'] ?? null)
            || ! $this->isBoundedInt($body['attempts_remaining'] ?? null, 0, 100)
            || ! $this->isBoundedInt($body['expires_in'] ?? null, 1, 86400)) {
            throw AccountDeletionException::invalidResponse($response->status());
        }

        return $body;
    }

    /** @param array<string, string> $traceHeaders */
    public function confirmAccountDeletionOtp(
        string $accessToken,
        string $challengeId,
        string $code,
        array $traceHeaders = [],
    ): AccountDeletionProof {
        return $this->confirmAccountDeletionOtpIdempotently(
            $accessToken,
            $challengeId,
            $code,
            (string) Str::uuid(),
            $traceHeaders,
        );
    }

    /** @param array<string, string> $traceHeaders */
    public function confirmAccountDeletionOtpIdempotently(
        string $accessToken,
        string $challengeId,
        string $code,
        string $idempotencyKey,
        array $traceHeaders = [],
    ): AccountDeletionProof {
        try {
            $response = $this->withTraceHeaders(
                $this->userRequest($accessToken)->withHeader('Idempotency-Key', $idempotencyKey),
                $traceHeaders,
            )->post($this->url('/api/identity/me/account-deletion/otp/confirm'), [
                'challenge_id' => $challengeId,
                'code' => $code,
            ]);
        } catch (\Throwable) {
            throw AccountDeletionException::transportFailure();
        }

        $body = $this->accountDeletionJson($response);
        if (! $this->isNonEmptyString($body['access_token'] ?? null)
            || ! $this->isNonEmptyString($body['refresh_token'] ?? null)
            || ! $this->isBoundedInt($body['expires_in'] ?? null, 1, 86400)) {
            throw AccountDeletionException::invalidResponse($response->status());
        }

        return AccountDeletionProof::fromArray($body);
    }

    /**
     * @param  array<string, string>  $traceHeaders
     * @return array{identity_id: string, revoked_sessions: int}
     */
    public function revokeAllSessions(string $identityId, array $traceHeaders = []): array
    {
        try {
            $response = $this->withTraceHeaders(
                $this->serviceRequest(),
                $traceHeaders,
            )->post($this->url("/api/service/users/{$identityId}/sessions/revoke-all"));
        } catch (\Throwable) {
            throw AccountDeletionException::transportFailure();
        }

        $body = $this->accountDeletionJson($response);
        if (! isset($body['identity_id'])
            || ! is_string($body['identity_id'])
            || ! hash_equals($identityId, $body['identity_id'])
            || ! $this->isBoundedInt($body['revoked_sessions'] ?? null, 0, PHP_INT_MAX)) {
            throw AccountDeletionException::invalidResponse($response->status());
        }

        return $body;
    }

    /**
     * @param  array<string, string>  $traceHeaders
     * @return array{identity_id: string, erased: bool, already_erased: bool, erased_at: string}
     */
    public function eraseIdentity(
        string $identityId,
        string $adminId,
        string $idempotencyKey,
        array $traceHeaders = [],
    ): array {
        $request = $this->withTraceHeaders($this->serviceRequest(), $traceHeaders)
            ->withHeader('Idempotency-Key', $idempotencyKey);

        try {
            $response = $request->post(
                $this->url("/api/service/users/{$identityId}/erase"),
                ['admin_id' => $adminId],
            );
        } catch (\Throwable) {
            throw AccountDeletionException::transportFailure();
        }

        $body = $this->accountDeletionJson($response);
        if (! isset($body['identity_id'])
            || ! is_string($body['identity_id'])
            || ! hash_equals($identityId, $body['identity_id'])
            || ($body['erased'] ?? null) !== true
            || ! is_bool($body['already_erased'] ?? null)
            || ! $this->isDateTime($body['erased_at'] ?? null)) {
            throw AccountDeletionException::invalidResponse($response->status());
        }

        return $body;
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
        return $this->json($this->request()->attach('file', fopen($filePath, 'rb'), $fileName)->post($uploadUrl));
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
        return $this->json($this->request()->attach('file', fopen($filePath, 'rb'), $fileName)->post($uploadUrl));
    }

    public function submitKycDraft(string $accessToken, string $submissionId, string $idempotencyKey): KycSubmission
    {
        return KycSubmission::fromArray($this->json($this->userRequest($accessToken)->post(
            $this->url("/api/identity/me/kyc/drafts/{$submissionId}/submit"),
            ['idempotency_key' => $idempotencyKey],
        )));
    }

    /** @return array{data: list<KycReviewItem>, meta: array} */
    public function listKycReviews(?string $status = null): array
    {
        $body = $this->json($this->serviceRequest()->get(
            $this->url('/api/service/kyc/reviews'),
            array_filter(['status' => $status]),
        ));
        $body['data'] = array_map(KycReviewItem::fromArray(...), $body['data'] ?? []);

        return $body;
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

    private function accountDeletionJson(Response $response): array
    {
        if ($response->failed()) {
            $status = $response->status();
            $upstreamCode = $response->json('error');
            $allowedCodes = [
                'too_many_requests' => 429,
                'too_many_attempts' => 429,
                'otp_unavailable' => 503,
                'internal_error' => 500,
                'invalid_challenge' => 422,
                'not_found' => 404,
                'idempotency_conflict' => 409,
                'idempotency_expired' => 409,
                'deletion_actor_forbidden' => 403,
            ];
            $code = is_string($upstreamCode) && ($allowedCodes[$upstreamCode] ?? null) === $status
                ? $upstreamCode
                : match (true) {
                    $status === 401 => 'authentication_failed',
                    $status === 403 => 'forbidden',
                    $status === 404 => 'not_found',
                    $status === 409 => 'conflict',
                    $status === 422 => 'validation_failed',
                    $status === 429 => 'rate_limited',
                    $status >= 500 => 'service_unavailable',
                    default => 'request_failed',
                };
            $category = match (true) {
                $status === 401 => 'authentication',
                $status === 403 => 'authorization',
                $status === 404 => 'not_found',
                $status === 409 => 'conflict',
                $status === 422 => 'validation',
                $status === 429 => 'rate_limited',
                $status >= 500 => 'server',
                default => 'request',
            };
            $retryAfter = $response->json('retry_after');

            throw new AccountDeletionException(
                $category,
                $code,
                $status,
                is_int($retryAfter) && $retryAfter >= 0 && $retryAfter <= 86400 ? $retryAfter : null,
            );
        }

        return $response->json() ?? [];
    }

    /** @param array<string, string> $headers */
    private function withTraceHeaders(PendingRequest $request, array $headers): PendingRequest
    {
        $traceHeaders = [];

        foreach ($headers as $name => $value) {
            $canonicalName = match (strtolower($name)) {
                'traceparent' => 'traceparent',
                'tracestate' => 'tracestate',
                default => null,
            };

            if ($canonicalName !== null && $value !== '') {
                $traceHeaders[$canonicalName] = $value;
            }
        }

        return $traceHeaders === [] ? $request : $request->withHeaders($traceHeaders);
    }

    private function isNonEmptyString(mixed $value): bool
    {
        return is_string($value) && trim($value) !== '';
    }

    private function isBoundedInt(mixed $value, int $minimum, int $maximum): bool
    {
        return is_int($value) && $value >= $minimum && $value <= $maximum;
    }

    private function isUuid(mixed $value): bool
    {
        return is_string($value)
            && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iD', $value) === 1;
    }

    private function isDateTime(mixed $value): bool
    {
        if (! $this->isNonEmptyString($value)) {
            return false;
        }

        try {
            new DateTimeImmutable($value);

            return true;
        } catch (\Exception) {
            return false;
        }
    }

    private function url(string $path): string
    {
        return rtrim((string) (config('identity-bridge.internal_url') ?: config('identity-bridge.url')), '/').$path;
    }
}
