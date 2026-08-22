<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Events;

class UserKycUpdated
{
    public function __construct(
        public readonly string $identity_id,
        public readonly int $kyc_tier,
        public readonly ?bool $is_of_legal_age,
        public readonly ?string $verified_at,
        public readonly ?string $revoked_at,
        public readonly ?string $submission_id = null,
        public readonly ?int $submission_version = null,
        public readonly ?int $record_version = null,
        public readonly ?string $status = null,
        public readonly ?string $decision_at = null,
        public readonly ?string $rejection_note = null,
    ) {}
}
