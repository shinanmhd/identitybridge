<?php

use App\Models\User;

return [
    'url' => env('IDENTITY_BRIDGE_URL'),
    // Server-to-server URL (used for token exchange inside Docker/Sail).
    // Defaults to IDENTITY_BRIDGE_URL when not set.
    // Set this to http://host.docker.internal:PORT when both apps run in Docker.
    'internal_url' => env('IDENTITY_BRIDGE_INTERNAL_URL'),
    'client_id' => env('IDENTITY_BRIDGE_CLIENT_ID'),
    'client_secret' => env('IDENTITY_BRIDGE_CLIENT_SECRET'),
    'webhook_secret' => env('IDENTITY_BRIDGE_WEBHOOK_SECRET'),
    'jwks_url' => env('IDENTITY_BRIDGE_JWKS_URL'),
    'issuer' => env('IDENTITY_BRIDGE_ISSUER'),
    'audience' => env('IDENTITY_BRIDGE_AUDIENCE'),
    'kyc_url' => env('IDENTITY_BRIDGE_KYC_URL'),
    'webhook_path' => env('IDENTITY_BRIDGE_WEBHOOK_PATH', 'webhooks/identity'),
    'register_webhook_route' => true,
    'user_model' => env('IDENTITY_BRIDGE_USER_MODEL', User::class),
    'cache_prefix' => 'ib_sdk_',
    'jwks_ttl' => 3600,
    'service_token_ttl' => 3500,
    'jwt_leeway' => 30,
    'http' => [
        'timeout' => (int) env('IDENTITY_BRIDGE_HTTP_TIMEOUT', 5),
        'connect_timeout' => (int) env('IDENTITY_BRIDGE_CONNECT_TIMEOUT', 2),
        'retries' => (int) env('IDENTITY_BRIDGE_HTTP_RETRIES', 1),
    ],

    // The slug of this application as registered in IdentityBridge Central
    'app_slug' => env('IDENTITY_BRIDGE_APP_SLUG', ''),

    // Optional: inline public key (falls back to storage/oauth-public.key)
    'public_key' => env('IDENTITY_BRIDGE_PUBLIC_KEY', null),

    'admin_sso' => [
        'callback_route' => env('IB_SSO_CALLBACK_ROUTE', 'admin.sso.callback'),
        'success_redirect' => env('IB_SSO_SUCCESS_REDIRECT', '/admin/dashboard'),
        'error_redirect' => env('IB_SSO_ERROR_REDIRECT', '/admin/login'),
        'login_redirect' => env('IB_SSO_LOGIN_REDIRECT', '/admin/login'),
        'staff_table' => env('IB_SSO_STAFF_TABLE', 'staff_members'),
    ],
];
