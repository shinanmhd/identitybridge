<?php

namespace IgniteLabs\IdentityBridge\Tests;

use IgniteLabs\IdentityBridge\IdentityBridgeServiceProvider;
use IgniteLabs\IdentityBridge\Facades\Identity;
use Orchestra\Testbench\TestCase as BaseTestCase;

abstract class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app): array
    {
        return [
            IdentityBridgeServiceProvider::class,
        ];
    }

    protected function getPackageAliases($app): array
    {
        return [
            'Identity' => Identity::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('identity-bridge.issuer', 'https://identity.ignitlabs.mv');
        $app['config']->set('identity-bridge.audience', 'test-app');
        $app['config']->set('identity-bridge.jwks_url', 'https://identity.ignitlabs.mv/.well-known/jwks.json');
        $app['config']->set('identity-bridge.url', 'https://identity.ignitlabs.mv');
        $app['config']->set('identity-bridge.webhook_secret', 'test-webhook-secret-32-chars-long!');
        $app['config']->set('identity-bridge.client_id', 'test-client-id');
        $app['config']->set('identity-bridge.client_secret', 'test-client-secret');
        $app['config']->set('identity-bridge.cache_prefix', 'ib_sdk_');
        $app['config']->set('identity-bridge.register_webhook_route', true);
        $app['config']->set('identity-bridge.jwks_ttl', 3600);
        $app['config']->set('identity-bridge.jwt_leeway', 30);
        $app['config']->set('identity-bridge.service_token_ttl', 3500);
        $app['config']->set('cache.default', 'array');
    }
}
