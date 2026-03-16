<?php

use IgniteLabs\IdentityBridge\Http\Middleware\ProvideShadowUser;
use IgniteLabs\IdentityBridge\Identity\Contracts\ProvisionsShadowUser;
use IgniteLabs\IdentityBridge\Identity\IdentityClaims;
use IgniteLabs\IdentityBridge\Tests\Fixtures\KeyFixture;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

// Shared test guard that records setUser calls and can return the stored user
function makeTestGuard(): object
{
    return new class implements Guard
    {
        public ?Authenticatable $storedUser = null;

        public function check(): bool
        {
            return $this->storedUser !== null;
        }

        public function guest(): bool
        {
            return ! $this->check();
        }

        public function user(): ?Authenticatable
        {
            return $this->storedUser;
        }

        public function id(): mixed
        {
            return $this->storedUser?->getAuthIdentifier();
        }

        public function validate(array $credentials = []): bool
        {
            return false;
        }

        public function hasUser(): bool
        {
            return $this->storedUser !== null;
        }

        public function setUser(Authenticatable $user): static
        {
            $this->storedUser = $user;

            return $this;
        }
    };
}

beforeEach(function () {
    // Register a simple, stateless identity guard for middleware to call setUser() on
    $this->testGuard = makeTestGuard();
    Auth::extend('test_identity', fn () => $this->testGuard);
    config()->set('auth.guards.identity', ['driver' => 'test_identity']);
});

it('missing claims attribute returns 401', function () {
    $request = Request::create('/test', 'GET');
    $middleware = new ProvideShadowUser;
    $response = $middleware->handle($request, fn ($r) => response('ok'));

    expect($response->getStatusCode())->toBe(401)
        ->and($response->getData(true)['error'])->toBe('Unauthorized');
});

it('unbound ProvisionsShadowUser contract throws LogicException', function () {
    $claims = new IdentityClaims(KeyFixture::makeClaims());
    $request = Request::create('/test', 'GET');
    $request->attributes->set('identity_claims', $claims);

    // Explicitly ensure nothing is bound
    $middleware = new ProvideShadowUser;

    expect(fn () => $middleware->handle($request, fn ($r) => response('ok')))
        ->toThrow(LogicException::class, 'App must bind ProvisionsShadowUser contract');
});

it('calls provision() on the provisioner with the correct IdentityClaims', function () {
    $claims = new IdentityClaims(KeyFixture::makeClaims());
    $user = new GenericUser(['id' => 42]);

    $provisioner = Mockery::mock(ProvisionsShadowUser::class);
    $provisioner->shouldReceive('provision')->once()->with($claims)->andReturn($user);
    app()->instance(ProvisionsShadowUser::class, $provisioner);

    $request = Request::create('/test', 'GET');
    $request->attributes->set('identity_claims', $claims);

    $middleware = new ProvideShadowUser;
    $response = $middleware->handle($request, fn ($r) => response('ok'));

    expect($response->getStatusCode())->toBe(200);
});

it('sets the provisioned user on Auth::guard(identity) via setUser()', function () {
    $claims = new IdentityClaims(KeyFixture::makeClaims());
    $user = new GenericUser(['id' => 99]);

    $provisioner = Mockery::mock(ProvisionsShadowUser::class);
    $provisioner->shouldReceive('provision')->andReturn($user);
    app()->instance(ProvisionsShadowUser::class, $provisioner);

    $request = Request::create('/test', 'GET');
    $request->attributes->set('identity_claims', $claims);

    $middleware = new ProvideShadowUser;
    $middleware->handle($request, fn ($r) => response('ok'));

    expect($this->testGuard->storedUser)->toBe($user);
});

it('provision result is accessible via Auth::guard(identity)->user() after middleware', function () {
    $claims = new IdentityClaims(KeyFixture::makeClaims());
    $user = new GenericUser(['id' => 77]);

    $provisioner = Mockery::mock(ProvisionsShadowUser::class);
    $provisioner->shouldReceive('provision')->andReturn($user);
    app()->instance(ProvisionsShadowUser::class, $provisioner);

    $request = Request::create('/test', 'GET');
    $request->attributes->set('identity_claims', $claims);

    $middleware = new ProvideShadowUser;
    $middleware->handle($request, fn ($r) => response('ok'));

    expect(Auth::guard('identity')->user())->toBe($user);
});
