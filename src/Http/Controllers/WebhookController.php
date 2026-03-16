<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use IgniteLabs\IdentityBridge\Events\GhostCreated;
use IgniteLabs\IdentityBridge\Events\KeyRotated;
use IgniteLabs\IdentityBridge\Events\TokenRevoked;
use IgniteLabs\IdentityBridge\Events\UserDeleted;
use IgniteLabs\IdentityBridge\Events\UserIdentityMerged;
use IgniteLabs\IdentityBridge\Events\UserKycUpdated;
use IgniteLabs\IdentityBridge\Events\UserPhoneUpdated;
use IgniteLabs\IdentityBridge\Events\UserRegistered;

class WebhookController
{
    private const KNOWN_EVENTS = [
        'user.registered',
        'user.kyc_updated',
        'user.phone_updated',
        'user.deleted',
        'ghost.created',
        'user.identity_merged',
        'token.revoked',
        'key.rotated',
    ];

    /** Maximum age of a webhook before it is rejected (seconds). */
    private const MAX_AGE_SECONDS = 300;

    /** How long to remember processed webhook JTIs (seconds). */
    private const JTI_TTL_SECONDS = 3600;

    public function handle(Request $request): JsonResponse
    {
        // Schema validation — reject malformed or unknown events early.
        $request->validate([
            'event'   => ['required', 'string', 'in:' . implode(',', self::KNOWN_EVENTS)],
            'payload' => ['required', 'array'],
        ]);

        $event   = $request->input('event');
        $payload = $request->input('payload', []);

        // Timestamp validation — reject stale webhooks (replay of old deliveries).
        if (isset($payload['timestamp'])) {
            $age = abs(time() - (int) $payload['timestamp']);
            if ($age > self::MAX_AGE_SECONDS) {
                return response()->json(['error' => 'Webhook timestamp too old'], 422);
            }
        }

        // Replay protection — deduplicate by JTI within a 1-hour window.
        if (isset($payload['jti'])) {
            $prefix   = config('identity-bridge.cache_prefix', 'ib_sdk_');
            $cacheKey = $prefix . 'webhook_jti:' . $payload['jti'];

            if (Cache::has($cacheKey)) {
                // Already processed — respond 200 to prevent IB from retrying.
                return response()->json(['ok' => true]);
            }

            Cache::put($cacheKey, true, self::JTI_TTL_SECONDS);
        }

        switch ($event) {
            case 'user.registered':
                event(new UserRegistered(
                    $payload['identity_id'],
                    $payload['ghost_identity_id'] ?? null,
                ));
                break;

            case 'user.kyc_updated':
                event(new UserKycUpdated(
                    $payload['identity_id'],
                    $payload['kyc_tier'],
                    $payload['is_of_legal_age'] ?? null,
                    $payload['verified_at'] ?? null,
                    $payload['revoked_at'] ?? null,
                ));
                break;

            case 'user.phone_updated':
                event(new UserPhoneUpdated(
                    $payload['identity_id'],
                    $payload['previous_phone_hash'],
                    $payload['updated_at'],
                ));
                break;

            case 'user.deleted':
                event(new UserDeleted(
                    $payload['identity_id'],
                    $payload['deleted_at'],
                ));
                break;

            case 'ghost.created':
                event(new GhostCreated(
                    $payload['ghost_id'],
                    $payload['phone_hash'],
                    $payload['source'],
                    $payload['created_at'],
                ));
                break;

            case 'user.identity_merged':
                event(new UserIdentityMerged(
                    $payload['identity_id'],
                    $payload['ghost_id'],
                    $payload['phone_hash'],
                    $payload['merged_at'],
                ));
                break;

            case 'token.revoked':
                event(new TokenRevoked(
                    $payload['jti'],
                    $payload['identity_id'],
                    $payload['revoked_at'],
                ));
                break;

            case 'key.rotated':
                event(new KeyRotated(
                    $payload['new_kid'],
                    $payload['transition_window_hours'],
                ));
                break;
        }

        return response()->json(['ok' => true]);
    }
}
