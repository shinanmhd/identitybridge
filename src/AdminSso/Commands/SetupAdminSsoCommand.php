<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\AdminSso\Commands;

use Illuminate\Console\Command;

class SetupAdminSsoCommand extends Command
{
    protected $signature   = 'identity-bridge:setup-admin-sso';
    protected $description = 'Publish Admin SSO configuration and migration scaffold';

    public function handle(): void
    {
        $this->call('vendor:publish', [
            '--tag'   => 'identity-bridge-admin-sso',
            '--force' => false,
        ]);

        $this->info('Admin SSO assets published.');
        $this->line('');
        $this->line('Next steps:');
        $this->line('  1. Add to config/identity-bridge.php:');
        $this->line('       admin_sso => [');
        $this->line("         'callback_route'   => 'admin.sso.callback',");
        $this->line("         'success_redirect' => '/admin/dashboard',");
        $this->line("         'error_redirect'   => '/',");
        $this->line("         'login_redirect'   => '/admin/login',");
        $this->line('       ]');
        $this->line('  2. Run: php artisan migrate');
        $this->line('  3. Register routes in routes/admin.php:');
        $this->line("       Route::get('/sso/redirect', [AdminSsoController::class, 'redirect'])->name('admin.sso.redirect');");
        $this->line("       Route::get('/sso/callback', [AdminSsoController::class, 'callback'])->name('admin.sso.callback');");
        $this->line('  4. Protect admin routes with middleware: require.staff');
    }
}
