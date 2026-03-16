<?php

return [
    'url'                    => env('IDENTITY_BRIDGE_URL'),
    'client_id'              => env('IDENTITY_BRIDGE_CLIENT_ID'),
    'client_secret'          => env('IDENTITY_BRIDGE_CLIENT_SECRET'),
    'webhook_secret'         => env('IDENTITY_BRIDGE_WEBHOOK_SECRET'),
    'jwks_url'               => env('IDENTITY_BRIDGE_JWKS_URL'),
    'issuer'                 => env('IDENTITY_BRIDGE_ISSUER', 'https://identity.ignitlabs.mv'),
    'audience'               => env('IDENTITY_BRIDGE_AUDIENCE'),
    'kyc_url'                => env('IDENTITY_BRIDGE_KYC_URL', 'https://identity.ignitlabs.mv/identity/verify'),
    'webhook_path'           => env('IDENTITY_BRIDGE_WEBHOOK_PATH', 'webhooks/identity'),
    'register_webhook_route' => true,
    'user_model'             => env('IDENTITY_BRIDGE_USER_MODEL', \App\Models\User::class),
    'cache_prefix'           => 'ib_sdk_',
    'jwks_ttl'               => 3600,
    'service_token_ttl'      => 3500,
    'jwt_leeway'             => 30,
];
