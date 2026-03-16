<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;

class JwtGuard implements Guard
{
    private ?Authenticatable $user = null;

    public function __construct(
        private readonly JwtValidator $validator,
        private readonly UserProvider $provider,
        private readonly Request $request,
    ) {}

    public function user(): ?Authenticatable
    {
        if ($this->user !== null) {
            return $this->user;
        }

        $token = $this->getTokenFromRequest();
        if ($token === null) {
            return null;
        }

        $claims = $this->validator->validate($token);
        if ($claims === null) {
            return null;
        }

        // Attach claims to request for identity() helper / middleware
        $this->request->attributes->set('identity_claims', $claims);

        // Look up local shadow user by identity_id = sub claim
        $user = $this->provider->retrieveByCredentials(['identity_id' => $claims->sub()]);
        if ($user === null) {
            return null;
        }

        $this->user = $user;
        return $this->user;
    }

    public function check(): bool
    {
        return $this->user() !== null;
    }

    public function guest(): bool
    {
        return ! $this->check();
    }

    public function id(): int|string|null
    {
        return $this->user()?->getAuthIdentifier();
    }

    public function validate(array $credentials = []): bool
    {
        return false; // JWT guard does not support credential-based validation
    }

    public function hasUser(): bool
    {
        return $this->user !== null;
    }

    public function setUser(Authenticatable $user): static
    {
        $this->user = $user;
        return $this;
    }

    private function getTokenFromRequest(): ?string
    {
        $header = $this->request->header('Authorization', '');
        if (str_starts_with($header, 'Bearer ')) {
            return substr($header, 7);
        }
        return null;
    }
}
