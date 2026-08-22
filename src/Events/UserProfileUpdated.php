<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Events;

final readonly class UserProfileUpdated
{
    public function __construct(
        public string $identity_id,
        public int $profile_version,
        public string $name,
        public ?string $email,
        public ?string $avatar_url,
        public ?int $avatar_version,
        public ?string $updated_at,
    ) {}
}
