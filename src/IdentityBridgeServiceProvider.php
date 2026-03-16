<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge;

use IgniteLabs\IdentityBridge\AdminSso\AdminSsoManager;
use IgniteLabs\IdentityBridge\AdminSso\Commands\SetupAdminSsoCommand;
use IgniteLabs\IdentityBridge\AdminSso\Http\Middleware\RequireStaffSession;
use IgniteLabs\IdentityBridge\AdminSso\StaffProvisioner;
use IgniteLabs\IdentityBridge\Auth\JwksProvider;
use IgniteLabs\IdentityBridge\Auth\JwtGuard;
use IgniteLabs\IdentityBridge\Auth\JwtValidator;
use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Commands\CheckConnectionCommand;
use IgniteLabs\IdentityBridge\Commands\ClearCacheCommand;
use IgniteLabs\IdentityBridge\Commands\InstallCommand;
use IgniteLabs\IdentityBridge\Commands\ReconcileCommand;
use IgniteLabs\IdentityBridge\Events\KeyRotated;
use IgniteLabs\IdentityBridge\Http\Middleware\ProvideShadowUser;
use IgniteLabs\IdentityBridge\Http\Middleware\RequireKycTier;
use IgniteLabs\IdentityBridge\Http\Middleware\VerifyWebhookSignature;
use IgniteLabs\IdentityBridge\Listeners\BustJwksCacheOnKeyRotation;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\ServiceProvider;

class IdentityBridgeServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/identity-bridge.php',
            'identity-bridge'
        );

        $this->app->singleton(JwksProvider::class);
        $this->app->singleton(JwtValidator::class);

        $this->app->singleton(AdminSsoManager::class, function ($app) {
            $publicKey = config('identity-bridge.public_key')
                ?: (file_exists(storage_path('oauth-public.key'))
                    ? file_get_contents(storage_path('oauth-public.key'))
                    : '');

            return new AdminSsoManager(
                http: $app->make(Factory::class),
                identityBridgeUrl: (string) config('identity-bridge.url', ''),
                publicKey: $publicKey,
                internalUrl: (string) config('identity-bridge.internal_url', ''),
            );
        });

        $this->app->singleton(StaffProvisioner::class, function () {
            return new StaffProvisioner(
                table: (string) config('identity-bridge.admin_sso.staff_table', 'staff_members'),
                clientAppId: (string) config('identity-bridge.client_id', ''),
            );
        });

        $this->app->singleton(IdentityBridgeClient::class, function ($app) {
            return new IdentityBridgeClient(
                $app->make(Factory::class)
            );
        });

        $this->app->alias(
            IdentityBridgeClient::class,
            'identity-bridge'
        );
    }

    public function boot(): void
    {
        $router = $this->app['router'];
        $router->aliasMiddleware('verify.webhook', VerifyWebhookSignature::class);
        $router->aliasMiddleware('provide.shadow', ProvideShadowUser::class);
        $router->aliasMiddleware('kyc', RequireKycTier::class);
        $router->aliasMiddleware('require.staff', RequireStaffSession::class);

        Auth::extend('identity', function ($app, $name, $config) {
            return new JwtGuard(
                $app->make(JwtValidator::class),
                Auth::createUserProvider($config['provider'] ?? 'users'),
                $app->make('request'),
            );
        });

        if (config('identity-bridge.register_webhook_route', true)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/webhooks.php');
        }

        Event::listen(KeyRotated::class, BustJwksCacheOnKeyRotation::class);

        if ($this->app->runningInConsole()) {
            $this->commands([
                InstallCommand::class,
                CheckConnectionCommand::class,
                ClearCacheCommand::class,
                ReconcileCommand::class,
                SetupAdminSsoCommand::class,
            ]);

            $this->publishes([
                __DIR__.'/../config/identity-bridge.php' => config_path('identity-bridge.php'),
            ], 'identity-bridge-config');

            $this->publishes([
                __DIR__.'/../database/migrations/' => database_path('migrations'),
            ], 'identity-bridge-migrations');

            $this->publishes([
                __DIR__.'/AdminSso/Migrations/' => database_path('migrations'),
            ], 'identity-bridge-admin-sso');
        }
    }
}
