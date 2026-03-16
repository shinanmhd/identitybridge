<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Events;

class UserIdentityMerged
{
    public function __construct(
        public readonly string $identity_id,
        public readonly string $ghost_id,
        public readonly string $phone_hash,
        public readonly string $merged_at,
    ) {}
}
