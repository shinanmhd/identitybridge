<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Facades;

use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use Illuminate\Support\Facades\Facade;

/**
 * @method static string getServiceToken()
 * @method static array getIdentity(string $identityId)
 * @method static bool revokeToken(string $jti)
 * @method static string refreshServiceToken()
 * @method static \IgniteLabs\IdentityBridge\Dto\Profile profile(string $accessToken)
 * @method static array requestProfileOtp(string $accessToken)
 * @method static array confirmProfileOtp(string $accessToken, string $challengeId, string $code)
 * @method static \IgniteLabs\IdentityBridge\Dto\Profile updateProfile(string $accessToken, string $grantToken, array $attributes)
 * @method static array authorizeAvatar(string $accessToken)
 * @method static array uploadAvatar(string $uploadUrl, string $filePath, string $fileName)
 * @method static \IgniteLabs\IdentityBridge\Dto\Profile finalizeAvatar(string $accessToken, string $uploadId)
 * @method static \IgniteLabs\IdentityBridge\Dto\KycSubmission createKycDraft(string $accessToken)
 * @method static \IgniteLabs\IdentityBridge\Dto\KycSubmission getKycDraft(string $accessToken, string $submissionId)
 * @method static \IgniteLabs\IdentityBridge\Dto\KycSubmission updateKycDraft(string $accessToken, string $submissionId, array $step)
 * @method static array authorizeKycEvidence(string $accessToken, string $submissionId, string $kind)
 * @method static array uploadKycEvidence(string $uploadUrl, string $filePath, string $fileName)
 * @method static \IgniteLabs\IdentityBridge\Dto\KycSubmission submitKycDraft(string $accessToken, string $submissionId, string $idempotencyKey)
 * @method static array listKycReviews(?string $status = null, ?int $page = null, ?int $perPage = null, ?string $search = null, ?string $claimState = null, ?string $sort = null, ?string $direction = null)
 * @method static \IgniteLabs\IdentityBridge\Dto\KycReviewItem getKycReview(string $submissionId)
 * @method static \IgniteLabs\IdentityBridge\Dto\KycReviewItem claimKycReview(string $submissionId, string $actorId, int $expectedVersion)
 * @method static \IgniteLabs\IdentityBridge\Dto\KycReviewItem releaseKycReview(string $submissionId, string $actorId, int $expectedVersion)
 * @method static array authorizeKycEvidenceView(string $submissionId, string $evidenceId, string $actorId)
 * @method static \IgniteLabs\IdentityBridge\Dto\KycReviewItem approveKycReview(string $submissionId, string $actorId, int $expectedVersion, string $idempotencyKey, array $checklist)
 * @method static \IgniteLabs\IdentityBridge\Dto\KycReviewItem rejectKycReview(string $submissionId, string $actorId, int $expectedVersion, string $idempotencyKey, string $note)
 *
 * @see IdentityBridgeClient
 */
class Identity extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'identity-bridge';
    }
}
