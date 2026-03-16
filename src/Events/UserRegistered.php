<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Events;

class UserRegistered
{
    public function __construct(
        public readonly string $identity_id,
        public readonly ?string $ghost_identity_id,
    ) {}
}
