<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Dto;

/**
 * Short-lived proof of fresh OTP authentication for an account-deletion flow.
 *
 * Callers must treat both token properties as secrets and must not persist or log them.
 */
final readonly class AccountDeletionProof
{
    public function __construct(
        public string $accessToken,
        public string $refreshToken,
        public int $expiresIn,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            (string) $data['access_token'],
            (string) $data['refresh_token'],
            (int) $data['expires_in'],
        );
    }
}
