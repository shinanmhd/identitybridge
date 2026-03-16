<?php

declare(strict_types=1);

use Illuminate\Console\Command;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;

beforeEach(function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(
            ['access_token' => 'svc-token'], 200
        ),
    ]);
});

it('is registered as an artisan command', function () {
    expect(array_keys(Artisan::all()))->toContain('identity-bridge:reconcile');
});

it('reports no orphans when all identities have shadow users', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/service/users*' => Http::response([
            'data' => [
                ['identity_id' => 'uuid-exists', 'kyc_tier' => 1, 'created_at' => '2026-01-01T00:00:00Z'],
            ],
            'meta' => ['total' => 1, 'per_page' => 100, 'current_page' => 1, 'last_page' => 1],
        ], 200),
    ]);

    // Fake the user model lookup — override config to use a model that always returns true
    config(['identity-bridge.user_model' => ReconcileTestUserAlwaysExists::class]);

    $this->artisan('identity-bridge:reconcile')
        ->expectsOutputToContain('All 1 identities have local shadow users')
        ->assertExitCode(0);
});

it('reports orphans when identity has no shadow user', function () {
    $mockClient = Mockery::mock(\IgniteLabs\IdentityBridge\Client\IdentityBridgeClient::class);
    $mockClient->shouldReceive('listUsers')
        ->once()
        ->andReturn((function () {
            yield [
                'data' => [['identity_id' => 'uuid-orphan', 'kyc_tier' => 0, 'created_at' => '2026-01-01T00:00:00Z']],
                'meta' => ['total' => 1, 'per_page' => 100, 'current_page' => 1, 'last_page' => 1],
            ];
        })());

    $this->app->instance(\IgniteLabs\IdentityBridge\Client\IdentityBridgeClient::class, $mockClient);
    config(['identity-bridge.user_model' => ReconcileTestUserNeverExists::class]);

    $exitCode = \Illuminate\Support\Facades\Artisan::call('identity-bridge:reconcile');
    $output   = \Illuminate\Support\Facades\Artisan::output();

    expect($output)->toContain('[orphan]')
        ->and($output)->toContain('uuid-orphan')
        ->and($output)->toContain('1 orphan(s) found');

    expect($exitCode)->toBe(Command::FAILURE);
});

it('dry-run shows warning and does not exit 0 when orphans exist', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/service/users*' => Http::response([
            'data' => [
                ['identity_id' => 'uuid-orphan-dry', 'kyc_tier' => 0, 'created_at' => '2026-01-01T00:00:00Z'],
            ],
            'meta' => ['total' => 1, 'per_page' => 100, 'current_page' => 1, 'last_page' => 1],
        ], 200),
    ]);

    config(['identity-bridge.user_model' => ReconcileTestUserNeverExists::class]);

    $this->artisan('identity-bridge:reconcile', ['--dry-run' => true])
        ->expectsOutputToContain('dry-run')
        ->expectsOutputToContain('[orphan]')
        ->assertExitCode(Command::FAILURE);
});

it('passes --since option to the client', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/service/users*' => Http::response([
            'data' => [],
            'meta' => ['total' => 0, 'per_page' => 100, 'current_page' => 1, 'last_page' => 1],
        ], 200),
    ]);

    config(['identity-bridge.user_model' => ReconcileTestUserAlwaysExists::class]);

    $this->artisan('identity-bridge:reconcile', ['--since' => '2026-01-01T00:00:00Z'])
        ->assertExitCode(0);

    Http::assertSent(fn ($req) => str_contains($req->url(), 'since='));
});

it('exits with failure and error message on HTTP error', function () {
    Http::fake([
        'https://identity.ignitlabs.mv/oauth/token' => Http::response(['access_token' => 'svc-token'], 200),
        'https://identity.ignitlabs.mv/api/service/users*' => Http::response(['error' => 'Unauthorized'], 401),
    ]);

    config(['identity-bridge.user_model' => ReconcileTestUserAlwaysExists::class]);

    $this->artisan('identity-bridge:reconcile')
        ->expectsOutputToContain('Failed to fetch users')
        ->assertExitCode(Command::FAILURE);
});

it('exits with failure when user model is invalid', function () {
    config(['identity-bridge.user_model' => 'App\\Models\\NonExistentModel']);

    $this->artisan('identity-bridge:reconcile')
        ->expectsOutputToContain('Could not resolve user model')
        ->assertExitCode(Command::FAILURE);
});

// ---------------------------------------------------------------------------
// Inline stub models for tests — no DB needed
// ---------------------------------------------------------------------------

class ReconcileTestUserAlwaysExists
{
    public static function where(string $col, mixed $val): static
    {
        return new static();
    }

    public function exists(): bool
    {
        return true;
    }
}

class ReconcileTestUserNeverExists
{
    public static function where(string $col, mixed $val): static
    {
        return new static();
    }

    public function exists(): bool
    {
        return false;
    }
}
