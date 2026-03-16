<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\AdminSso\Http\Controllers;

use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Str;
use IgniteLabs\IdentityBridge\AdminSso\AdminSsoManager;
use IgniteLabs\IdentityBridge\AdminSso\StaffProvisioner;
use RuntimeException;

class AdminSsoController extends Controller
{
    public function __construct(
        private AdminSsoManager  $manager,
        private StaffProvisioner $provisioner,
    ) {}

    /**
     * Step 1 — Initiate PKCE flow (app-initiated).
     * Stores PKCE verifier + state in session and redirects to IB.
     */
    public function redirect(Request $request): RedirectResponse
    {
        $pkce  = $this->manager->generatePkce();
        $state = Str::random(32);

        session([
            'ib_sso_verifier' => $pkce['verifier'],
            'ib_sso_state'    => $state,
        ]);

        $redirectUri = route(config('identity-bridge.admin_sso.callback_route', 'admin.sso.callback'));
        $appSlug     = config('identity-bridge.app_slug');

        return redirect($this->manager->buildAuthorizationUrl(
            appSlug:    $appSlug,
            redirectUri: $redirectUri,
            state:      $state,
            challenge:  $pkce['challenge'],
        ));
    }

    /**
     * Step 2 — Handle callback after IB redirects with code + verifier.
     * Exchanges code, decodes JWT, provisions staff member, writes session.
     */
    public function callback(Request $request): RedirectResponse
    {
        $code     = $request->query('code');
        $verifier = $request->query('code_verifier');

        if (! $code || ! $verifier) {
            return redirect(config('identity-bridge.admin_sso.error_redirect', '/'))
                ->with('ib_sso_error', 'Missing code or verifier.');
        }

        try {
            $redirectUri = route(config('identity-bridge.admin_sso.callback_route', 'admin.sso.callback'));
            $token       = $this->manager->exchangeCode($code, $verifier, $redirectUri);
            $claims      = $this->manager->decodeToken($token);

            if ($claims->isExpired()) {
                throw new RuntimeException('Staff identity token has expired.');
            }

            $result = $this->provisioner->provision($claims);

            session([
                'ib_staff_identity_id' => $claims->identityId,
                'ib_staff_member_id'   => $result['id'],
                'ib_staff_name'        => $claims->name,
                'ib_staff_email'       => $claims->email,
            ]);
        } catch (\Throwable $e) {
            return redirect(config('identity-bridge.admin_sso.error_redirect', '/'))
                ->with('ib_sso_error', $e->getMessage());
        }

        return redirect(config('identity-bridge.admin_sso.success_redirect', '/admin/dashboard'));
    }
}
