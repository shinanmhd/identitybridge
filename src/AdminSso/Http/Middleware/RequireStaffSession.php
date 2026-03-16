<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\AdminSso\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Protects routes that require an authenticated IB staff session.
 * The session key `ib_staff_identity_id` is set by AdminSsoController::callback().
 */
class RequireStaffSession
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! session('ib_staff_identity_id')) {
            if ($request->expectsJson()) {
                return response()->json(['error' => 'Unauthenticated staff session.'], 401);
            }

            return redirect(config('identity-bridge.admin_sso.login_redirect', '/admin/login'))
                ->with('ib_sso_error', 'Please sign in to continue.');
        }

        return $next($request);
    }
}
