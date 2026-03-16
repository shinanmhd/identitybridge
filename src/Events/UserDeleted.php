<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Events;

class UserDeleted
{
    public function __construct(
        public readonly string $identity_id,
        public readonly string $deleted_at,
    ) {}
}
