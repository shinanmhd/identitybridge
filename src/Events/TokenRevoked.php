<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Events;

use Illuminate\Support\Facades\Cache;

class TokenRevoked
{
    public function __construct(
        public readonly string $jti,
        public readonly string $identity_id,
        public readonly string $revoked_at,
    ) {
        Cache::put(
            config('identity-bridge.cache_prefix') . 'revoked:' . $this->jti,
            true,
            900,
        );
    }
}
