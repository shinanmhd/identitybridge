<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Commands;

use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Exceptions\IdentityBridgeException;
use Illuminate\Console\Command;

class ReconcileCommand extends Command
{
    protected $signature = 'identity-bridge:reconcile
                            {--since= : Only check identities created after this ISO 8601 timestamp}
                            {--dry-run : Report orphans without taking any action}
                            {--per-page=100 : Records per page when querying the server}';

    protected $description = 'Reconcile local shadow users against the Identity Bridge server';

    public function __construct(private readonly IdentityBridgeClient $client)
    {
        parent::__construct();
    }

    public function handle(): int
    {
        $since = $this->option('since') ?: null;
        $dryRun = (bool) $this->option('dry-run');
        $perPage = (int) $this->option('per-page');

        $userModel = $this->resolveUserModel();

        if ($userModel === null) {
            $this->error('Could not resolve user model. Check identity-bridge.user_model config.');

            return Command::FAILURE;
        }

        $this->info('Reconciling shadow users with Identity Bridge...');
        if ($dryRun) {
            $this->warn('  [dry-run] No changes will be made.');
        }
        $this->newLine();

        $checked = 0;
        $orphans = 0;

        try {
            foreach ($this->client->listUsers($since, $perPage) as $page) {
                foreach ($page['data'] ?? [] as $remote) {
                    $checked++;
                    $identityId = $remote['identity_id'];

                    $exists = $userModel::where('identity_id', $identityId)->exists();

                    if (! $exists) {
                        $orphans++;
                        $this->line(sprintf(
                            '  [orphan] %s  kyc_tier=%d  created=%s',
                            $identityId,
                            $remote['kyc_tier'],
                            $remote['created_at'],
                        ));
                    }
                }

                $meta = $page['meta'] ?? [];
                $this->line(sprintf(
                    '  Page %d/%d — checked %d identities so far...',
                    $meta['current_page'] ?? '?',
                    $meta['last_page'] ?? '?',
                    $checked,
                ));
            }
        } catch (IdentityBridgeException $e) {
            $this->error('Failed to fetch users from Identity Bridge: '.$e->getMessage());

            return Command::FAILURE;
        }

        $this->newLine();

        if ($orphans === 0) {
            $this->info("✓ All {$checked} identities have local shadow users. No orphans found.");
        } else {
            $this->warn("{$orphans} orphan(s) found out of {$checked} identities checked.");
            if ($dryRun) {
                $this->line('  Run without <comment>--dry-run</comment> to log orphans to your application.');
            }
        }

        return $orphans > 0 ? Command::FAILURE : Command::SUCCESS;
    }

    private function resolveUserModel(): ?string
    {
        $model = config('identity-bridge.user_model');

        if (! $model || ! class_exists($model)) {
            return null;
        }

        return $model;
    }
}
