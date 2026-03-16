<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Commands;

use Illuminate\Console\Command;

class InstallCommand extends Command
{
    protected $signature = 'identity-bridge:install';

    protected $description = 'Install the Identity Bridge SDK: publish config and migrations';

    public function handle(): int
    {
        $this->info('Installing Identity Bridge SDK...');
        $this->newLine();

        // Publish config
        $this->callSilently('vendor:publish', [
            '--tag' => 'identity-bridge-config',
            '--force' => false,
        ]);
        $this->line('  <fg=green;options=bold>✓</> Config published → <comment>config/identity-bridge.php</comment>');

        // Publish migrations
        $this->callSilently('vendor:publish', [
            '--tag' => 'identity-bridge-migrations',
            '--force' => false,
        ]);
        $this->line('  <fg=green;options=bold>✓</> Migrations published → <comment>database/migrations/</comment>');

        $this->newLine();
        $this->info('Next steps:');
        $this->newLine();
        $this->line('  <fg=yellow>1.</> Add to your <comment>.env</comment>:');
        $this->line('');
        $this->line('       IDENTITY_BRIDGE_URL=https://identity.ignitlabs.mv');
        $this->line('       IDENTITY_BRIDGE_CLIENT_ID=your-client-id');
        $this->line('       IDENTITY_BRIDGE_CLIENT_SECRET=your-client-secret');
        $this->line('       IDENTITY_BRIDGE_WEBHOOK_SECRET=your-webhook-secret');
        $this->line('       IDENTITY_BRIDGE_JWKS_URL=https://identity.ignitlabs.mv/.well-known/jwks.json');
        $this->line('       IDENTITY_BRIDGE_ISSUER=https://identity.ignitlabs.mv');
        $this->line('       IDENTITY_BRIDGE_AUDIENCE=your-app-slug');
        $this->newLine();
        $this->line('  <fg=yellow>2.</> Register the guard in <comment>config/auth.php</comment>:');
        $this->line('');
        $this->line("       'guards' => [");
        $this->line("           'identity' => ['driver' => 'identity', 'provider' => 'users'],");
        $this->line('       ],');
        $this->newLine();
        $this->line('  <fg=yellow>3.</> Bind the <comment>ProvisionsShadowUser</comment> contract in a service provider:');
        $this->line('');
        $this->line('       $this->app->bind(\\IgniteLabs\\IdentityBridge\\Identity\\Contracts\\ProvisionsShadowUser::class,');
        $this->line('           \\App\\Identity\\ShadowUserProvisioner::class);');
        $this->newLine();
        $this->line('  <fg=yellow>4.</> Add the webhook path to CSRF exceptions in <comment>bootstrap/app.php</comment>:');
        $this->line('');
        $this->line('       ->withMiddleware(function (Middleware $m) {');
        $this->line("           \$m->validateCsrfTokens(except: ['webhooks/identity']);");
        $this->line('       })');
        $this->newLine();
        $this->line('  <fg=yellow>5.</> Run migrations:');
        $this->line('');
        $this->line('       php artisan migrate');
        $this->newLine();
        $this->line('  <fg=yellow>6.</> Verify connectivity:');
        $this->line('');
        $this->line('       php artisan identity-bridge:check');
        $this->newLine();

        return Command::SUCCESS;
    }
}
