<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\AdminSso;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

/**
 * Provisions (or updates) the local staff member record from decoded JWT claims.
 * Uses raw DB façade to stay Eloquent-model-agnostic — the consuming app owns
 * its own `staff_members` table schema.
 */
final class StaffProvisioner
{
    public function __construct(
        private readonly string $table = 'staff_members',
        private readonly string $clientAppId = '',
    ) {}

    /**
     * Upsert a local staff record for the given claims.
     *
     * @return array{id: string, created: bool}
     */
    public function provision(StaffClaims $claims): array
    {
        $existing = DB::table($this->table)
            ->where('ib_identity_id', $claims->identityId)
            ->first();

        if ($existing) {
            DB::table($this->table)
                ->where('ib_identity_id', $claims->identityId)
                ->update([
                    'name' => $claims->name,
                    'email' => $claims->email,
                    'updated_at' => now(),
                ]);

            return ['id' => $existing->id, 'created' => false];
        }

        $id = (string) Str::uuid();

        DB::table($this->table)->insert([
            'id' => $id,
            'ib_identity_id' => $claims->identityId,
            'name' => $claims->name,
            'email' => $claims->email,
            'client_app_id' => $this->clientAppId ?: null,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return ['id' => $id, 'created' => true];
    }
}
