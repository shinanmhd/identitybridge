<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Identity\Contracts;

use IgniteLabs\IdentityBridge\Identity\IdentityClaims;
use Illuminate\Contracts\Auth\Authenticatable;

interface ProvisionsShadowUser
{
    /**
     * Provision (or retrieve) the local shadow user for the given identity claims.
     * Called automatically by the ProvideShadowUser middleware on first request.
     * Bind an implementation of this interface in the app service provider.
     */
    public function provision(IdentityClaims $claims): Authenticatable;
}
