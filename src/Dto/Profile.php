<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Dto;

final readonly class Profile
{
    public function __construct(
        public string $identityId,
        public string $phoneNumber,
        public string $name,
        public ?string $email,
        public ?string $avatarUrl,
        public ?int $avatarVersion,
        public int $profileVersion,
        public int $kycTier,
        public ?string $kycStatus,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            (string) $data['identity_id'],
            (string) $data['phone_number'],
            (string) $data['name'],
            isset($data['email']) ? (string) $data['email'] : null,
            isset($data['avatar_url']) ? (string) $data['avatar_url'] : null,
            isset($data['avatar_version']) ? (int) $data['avatar_version'] : null,
            (int) $data['profile_version'],
            (int) $data['kyc_tier'],
            isset($data['kyc_status']) ? (string) $data['kyc_status'] : null,
        );
    }
}
