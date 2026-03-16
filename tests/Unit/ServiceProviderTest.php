<?php

use IgniteLabs\IdentityBridge\Auth\JwksProvider;
use IgniteLabs\IdentityBridge\Auth\JwtGuard;
use IgniteLabs\IdentityBridge\Auth\JwtValidator;
use IgniteLabs\IdentityBridge\Client\IdentityBridgeClient;
use IgniteLabs\IdentityBridge\Commands\CheckConnectionCommand;
use IgniteLabs\IdentityBridge\Commands\ClearCacheCommand;
use Illuminate\Foundation\Auth\User;
use Illuminate\Support\Facades\Auth;

test('registers JwksProvider as singleton', function () {
    $a = $this->app->make(JwksProvider::class);
    $b = $this->app->make(JwksProvider::class);

    expect($a)->toBeInstanceOf(JwksProvider::class)
        ->and($a)->toBe($b);
});

test('registers JwtValidator as singleton', function () {
    $a = $this->app->make(JwtValidator::class);
    $b = $this->app->make(JwtValidator::class);

    expect($a)->toBeInstanceOf(JwtValidator::class)
        ->and($a)->toBe($b);
});

test('registers IdentityBridgeClient as singleton', function () {
    $a = $this->app->make(IdentityBridgeClient::class);
    $b = $this->app->make(IdentityBridgeClient::class);

    expect($a)->toBeInstanceOf(IdentityBridgeClient::class)
        ->and($a)->toBe($b);
});

test('registers identity auth guard driver', function () {
    $this->app['config']->set('auth.guards.identity', [
        'driver' => 'identity',
        'provider' => 'users',
    ]);
    $this->app['config']->set('auth.providers.users', [
        'driver' => 'eloquent',
        'model' => User::class,
    ]);

    $guard = Auth::guard('identity');

    expect($guard)->toBeInstanceOf(JwtGuard::class);
});

test('registers middleware aliases', function () {
    $middleware = $this->app['router']->getMiddleware();

    expect($middleware)
        ->toHaveKey('verify.webhook')
        ->toHaveKey('provide.shadow')
        ->toHaveKey('kyc');
});

test('registers artisan commands', function () {
    $checkCmd = $this->app->make(CheckConnectionCommand::class);
    $clearCmd = $this->app->make(ClearCacheCommand::class);

    expect($checkCmd->getName())->toBe('identity-bridge:check')
        ->and($clearCmd->getName())->toBe('identity-bridge:clear-cache');
});
