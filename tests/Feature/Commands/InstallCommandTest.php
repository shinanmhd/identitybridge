<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;

it('publishes config and outputs next-step instructions', function () {
    $this->artisan('identity-bridge:install')
        ->expectsOutputToContain('Installing Identity Bridge SDK')
        ->expectsOutputToContain('Config published')
        ->expectsOutputToContain('Migrations published')
        ->expectsOutputToContain('Next steps')
        ->expectsOutputToContain('IDENTITY_BRIDGE_URL')
        ->expectsOutputToContain("'driver' => 'identity'")
        ->expectsOutputToContain('ProvisionsShadowUser')
        ->expectsOutputToContain('webhooks/identity')
        ->expectsOutputToContain('identity-bridge:check')
        ->assertExitCode(0);
});

it('is registered as an artisan command', function () {
    expect(array_keys(Artisan::all()))->toContain('identity-bridge:install');
});
