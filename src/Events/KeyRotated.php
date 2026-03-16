<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Events;

class KeyRotated
{
    public function __construct(
        public readonly string $new_kid,
        public readonly int $transition_window_hours,
    ) {}
}
