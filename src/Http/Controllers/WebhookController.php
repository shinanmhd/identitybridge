<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
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
    public function handle(Request $request): JsonResponse
    {
        $event   = $request->input('event');
        $payload = $request->input('payload', []);

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

            default:
                return response()->json(['error' => 'Unknown event'], 422);
        }

        return response()->json(['ok' => true]);
    }
}
