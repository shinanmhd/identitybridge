<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Http\Middleware;

use Closure;
use IgniteLabs\IdentityBridge\Identity\IdentityClaims;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequireKycTier
{
    public function handle(Request $request, Closure $next, int|string $tier = 1): Response
    {
        $tier = (int) $tier;
        $claims = $request->attributes->get('identity_claims');

        if (! $claims instanceof IdentityClaims) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        if ($claims->kycTier() < $tier) {
            return response()->json([
                'error' => 'KYC verification required',
                'required_tier' => $tier,
                'verify_url' => config('identity-bridge.kyc_url'),
            ], 403);
        }

        return $next($request);
    }
}
