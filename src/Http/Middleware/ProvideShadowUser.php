<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Http\Middleware;

use Closure;
use IgniteLabs\IdentityBridge\Identity\Contracts\ProvisionsShadowUser;
use IgniteLabs\IdentityBridge\Identity\IdentityClaims;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class ProvideShadowUser
{
    public function handle(Request $request, Closure $next): Response
    {
        $claims = $request->attributes->get('identity_claims');

        if (! $claims instanceof IdentityClaims) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        if (! app()->bound(ProvisionsShadowUser::class)) {
            throw new \LogicException('App must bind ProvisionsShadowUser contract');
        }

        /** @var ProvisionsShadowUser $provisioner */
        $provisioner = app(ProvisionsShadowUser::class);
        $user = $provisioner->provision($claims);

        Auth::guard('identity')->setUser($user);

        return $next($request);
    }
}
