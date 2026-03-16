<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Events;

class GhostCreated
{
    public function __construct(
        public readonly string $ghost_id,
        public readonly string $phone_hash,
        public readonly string $source,
        public readonly string $created_at,
    ) {}
}
