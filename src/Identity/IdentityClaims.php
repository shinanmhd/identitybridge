<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Identity;

use Carbon\Carbon;

class IdentityClaims
{
    public function __construct(private readonly array $claims) {}

    public function sub(): string
    {
        return $this->claims['sub'];
    }

    public function kycTier(): int
    {
        return (int) ($this->claims['kyc_tier'] ?? 0);
    }

    public function isVerified(): bool
    {
        return $this->kycTier() >= 1;
    }

    public function isFullKyc(): bool
    {
        return $this->kycTier() >= 2;
    }

    public function isAmlCleared(): bool
    {
        return $this->kycTier() >= 3;
    }

    public function isOfLegalAge(): bool
    {
        return (bool) ($this->claims['is_of_legal_age'] ?? false);
    }

    public function phoneVerified(): bool
    {
        return (bool) ($this->claims['phone_verified'] ?? false);
    }

    public function ghostIdentityId(): ?string
    {
        return $this->claims['ghost_identity_id'] ?? null;
    }

    public function jti(): string
    {
        return $this->claims['jti'];
    }

    public function expiresAt(): Carbon
    {
        return Carbon::createFromTimestamp($this->claims['exp']);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->claims[$key] ?? $default;
    }

    public function toArray(): array
    {
        return $this->claims;
    }
}
