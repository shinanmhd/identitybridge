<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Events;

class UserPhoneUpdated
{
    public function __construct(
        public readonly string $identity_id,
        public readonly string $previous_phone_hash,
        public readonly string $updated_at,
    ) {}
}
