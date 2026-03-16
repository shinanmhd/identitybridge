<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge;

use IgniteLabs\IdentityBridge\AdminSso\AdminSsoManager;
use IgniteLabs\IdentityBridge\AdminSso\Commands\SetupAdminSsoCommand;
use IgniteLabs\IdentityBridge\AdminSso\Http\Middleware\RequireStaffSession;
use IgniteLabs\IdentityBridge\AdminSso\StaffProvisioner;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;
use IgniteLabs\IdentityBridge\Auth\JwksProvider;
use IgniteLabs\IdentityBridge\Auth\JwtGuard;
use IgniteLabs\IdentityBridge\Auth\JwtValidator;
use IgniteLabs\IdentityBridge\Events\KeyRotated;
use IgniteLabs\IdentityBridge\Listeners\BustJwksCacheOnKeyRotation;

class IdentityBridgeServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/identity-bridge.php',
            'identity-bridge'
        );

        $this->app->singleton(JwksProvider::class);
        $this->app->singleton(JwtValidator::class);

        $this->app->singleton(AdminSsoManager::class, function ($app) {
            $publicKey = config('identity-bridge.public_key')
                ?? (file_exists(storage_path('oauth-public.key'))
                    ? file_get_contents(storage_path('oauth-public.key'))
                    : '');

            return new AdminSsoManager(
                http:              $app->make(\Illuminate\Http\Client\Factory::class),
                identityBridgeUrl: config('identity-bridge.base_url', ''),
                publicKey:         $publicKey,
            );
        });

        $this->app->singleton(StaffProvisioner::class, function () {
            return new StaffProvisioner(
                table:       config('identity-bridge.admin_sso.staff_table', 'staff_members'),
                clientAppId: config('identity-bridge.client_id', ''),
            );
        });

        $this->app->singleton(\IgniteLabs\IdentityBridge\Client\IdentityBridgeClient::class, function ($app) {
            return new \IgniteLabs\IdentityBridge\Client\IdentityBridgeClient(
                $app->make(\Illuminate\Http\Client\Factory::class)
            );
        });

        $this->app->alias(
            \IgniteLabs\IdentityBridge\Client\IdentityBridgeClient::class,
            'identity-bridge'
        );
    }

    public function boot(): void
    {
        $router = $this->app['router'];
        $router->aliasMiddleware('verify.webhook', \IgniteLabs\IdentityBridge\Http\Middleware\VerifyWebhookSignature::class);
        $router->aliasMiddleware('provide.shadow', \IgniteLabs\IdentityBridge\Http\Middleware\ProvideShadowUser::class);
        $router->aliasMiddleware('kyc', \IgniteLabs\IdentityBridge\Http\Middleware\RequireKycTier::class);
        $router->aliasMiddleware('require.staff', RequireStaffSession::class);

        Auth::extend('identity', function ($app, $name, $config) {
            return new JwtGuard(
                $app->make(JwtValidator::class),
                Auth::createUserProvider($config['provider'] ?? 'users'),
                $app->make('request'),
            );
        });

        if (config('identity-bridge.register_webhook_route', true)) {
            $this->loadRoutesFrom(__DIR__ . '/../routes/webhooks.php');
        }

        Event::listen(KeyRotated::class, BustJwksCacheOnKeyRotation::class);

        if ($this->app->runningInConsole()) {
            $this->commands([
                \IgniteLabs\IdentityBridge\Commands\InstallCommand::class,
                \IgniteLabs\IdentityBridge\Commands\CheckConnectionCommand::class,
                \IgniteLabs\IdentityBridge\Commands\ClearCacheCommand::class,
                \IgniteLabs\IdentityBridge\Commands\ReconcileCommand::class,
                SetupAdminSsoCommand::class,
            ]);

            $this->publishes([
                __DIR__ . '/../config/identity-bridge.php' => config_path('identity-bridge.php'),
            ], 'identity-bridge-config');

            $this->publishes([
                __DIR__ . '/../database/migrations/' => database_path('migrations'),
            ], 'identity-bridge-migrations');

            $this->publishes([
                __DIR__ . '/AdminSso/Migrations/' => database_path('migrations'),
            ], 'identity-bridge-admin-sso');
        }
    }
}
