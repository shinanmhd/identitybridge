<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;

class ClearCacheCommand extends Command
{
    protected $signature = 'identity-bridge:clear-cache';

    protected $description = 'Clear all Identity Bridge SDK cache entries';

    public function handle(): int
    {
        $prefix = config('identity-bridge.cache_prefix', 'ib_sdk_');

        Cache::forget($prefix . 'jwks');
        Cache::forget($prefix . 'service_token');

        $this->info('Identity Bridge SDK cache cleared.');

        return Command::SUCCESS;
    }
}
