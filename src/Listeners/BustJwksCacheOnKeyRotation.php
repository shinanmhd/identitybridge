<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Listeners;

use IgniteLabs\IdentityBridge\Auth\JwksProvider;
use IgniteLabs\IdentityBridge\Events\KeyRotated;

class BustJwksCacheOnKeyRotation
{
    public function __construct(private readonly JwksProvider $jwks) {}

    public function handle(KeyRotated $event): void
    {
        $this->jwks->rotateCache();
    }
}
