<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\AdminSso;

use InvalidArgumentException;

/**
 * Value object wrapping the decoded staff identity JWT claims.
 */
final class StaffClaims
{
    public function __construct(
        public readonly string $sub,
        public readonly string $identityId,
        public readonly string $name,
        public readonly string $email,
        public readonly bool $isStaff,
        public readonly string $audience,
        public readonly string $issuer,
        public readonly int $issuedAt,
        public readonly int $expiresAt,
        public readonly string $jti,
    ) {}

    public static function fromPayload(object $payload): self
    {
        if (! isset($payload->is_staff) || ! $payload->is_staff) {
            throw new InvalidArgumentException('JWT is not a staff identity token.');
        }

        return new self(
            sub: $payload->sub,
            identityId: $payload->identity_id,
            name: $payload->name,
            email: $payload->email,
            isStaff: (bool) $payload->is_staff,
            audience: is_array($payload->aud) ? $payload->aud[0] : $payload->aud,
            issuer: $payload->iss,
            issuedAt: (int) $payload->iat,
            expiresAt: (int) $payload->exp,
            jti: $payload->jti,
        );
    }

    public function isExpired(): bool
    {
        return time() > $this->expiresAt;
    }
}
