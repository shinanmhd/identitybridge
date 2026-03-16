<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Commands;

use Illuminate\Console\Command;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;
use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Exceptions\IdentityBridgeException;

class CheckConnectionCommand extends Command
{
    protected $signature = 'identity-bridge:check';

    protected $description = 'Check connectivity to the Identity Bridge server';

    public function __construct(private readonly IdentityBridgeClient $client)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $url     = config('identity-bridge.url');
        $success = true;

        try {
            $response = Http::get($url . '/health');

            if ($response->successful()) {
                $this->info("✓ Identity Bridge is reachable at {$url}");
            } else {
                $this->error("✗ Cannot reach Identity Bridge at {$url}: HTTP {$response->status()}");
                $success = false;
            }
        } catch (ConnectionException $e) {
            $this->error("✗ Cannot reach Identity Bridge at {$url}: {$e->getMessage()}");
            $success = false;
        }

        try {
            $this->client->getServiceToken();
            $this->info('✓ Service token obtained successfully');
        } catch (IdentityBridgeException $e) {
            $this->error("✗ Failed to obtain service token: {$e->getMessage()}");
            $success = false;
        }

        return $success ? Command::SUCCESS : Command::FAILURE;
    }
}
