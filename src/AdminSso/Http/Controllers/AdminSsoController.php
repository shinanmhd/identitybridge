<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\AdminSso\Http\Controllers;

use IgniteLabs\IdentityBridge\AdminSso\AdminSsoManager;
use IgniteLabs\IdentityBridge\AdminSso\StaffProvisioner;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;
use RuntimeException;

class AdminSsoController extends Controller
{
    public function __construct(
        private AdminSsoManager $manager,
        private StaffProvisioner $provisioner,
    ) {}

    /**
     * Step 1 — Initiate PKCE flow (app-initiated).
     * Stores PKCE verifier + state in session and redirects to IB.
     */
    public function redirect(Request $request): RedirectResponse
    {
        $pkce = $this->manager->generatePkce();
        $state = Str::random(32);

        session([
            'ib_sso_verifier' => $pkce['verifier'],
            'ib_sso_state' => $state,
        ]);

        $redirectUri = route(config('identity-bridge.admin_sso.callback_route', 'admin.sso.callback'));
        $clientId = (string) config('identity-bridge.client_id', '');

        return redirect($this->manager->buildAuthorizationUrl(
            clientId: $clientId,
            redirectUri: $redirectUri,
            state: $state,
            challenge: $pkce['challenge'],
        ));
    }

    /**
     * Step 2 — Handle callback after IB redirects with code + state.
     * Verifier is read from session (never sent over the wire by IB).
     * Exchanges code, decodes JWT, provisions staff member, writes session.
     */
    public function callback(Request $request): RedirectResponse
    {
        $code = $request->query('code');
        $state = $request->query('state');
        $verifier = session('ib_sso_verifier');

        // Validate state to prevent CSRF
        if ($state && session('ib_sso_state') !== $state) {
            return redirect(config('identity-bridge.admin_sso.error_redirect', '/admin/login'))
                ->with('ib_sso_error', 'Invalid state parameter. Please try again.');
        }

        if (! $code || ! $verifier) {
            return redirect(config('identity-bridge.admin_sso.error_redirect', '/admin/login'))
                ->with('ib_sso_error', 'Missing code or verifier.');
        }

        session()->forget(['ib_sso_verifier', 'ib_sso_state']);

        try {
            $redirectUri = route(config('identity-bridge.admin_sso.callback_route', 'admin.sso.callback'));
            $clientId = (string) config('identity-bridge.client_id', '');
            $token = $this->manager->exchangeCode($code, $verifier, $redirectUri, $clientId);
            $claims = $this->manager->decodeToken($token);

            if ($claims->isExpired()) {
                throw new RuntimeException('Staff identity token has expired.');
            }

            $result = $this->provisioner->provision($claims);

            session([
                'ib_staff_identity_id' => $claims->identityId,
                'ib_staff_member_id' => $result['id'],
                'ib_staff_name' => $claims->name,
                'ib_staff_email' => $claims->email,
            ]);
        } catch (\Throwable $e) {
            Log::error('[IdentityBridge] SSO callback failed', [
                'error' => $e->getMessage(),
                'exception' => get_class($e),
                'trace' => $e->getTraceAsString(),
            ]);

            return redirect(config('identity-bridge.admin_sso.error_redirect', '/admin/login'))
                ->with('ib_sso_error', $e->getMessage());
        }

        return redirect(config('identity-bridge.admin_sso.success_redirect', '/admin/dashboard'));
    }
}
