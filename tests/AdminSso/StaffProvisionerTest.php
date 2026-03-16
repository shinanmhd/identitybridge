<?php

use IgniteLabs\IdentityBridge\AdminSso\StaffClaims;
use IgniteLabs\IdentityBridge\AdminSso\StaffProvisioner;
use Illuminate\Support\Facades\DB;

function makeStaffClaims(string $id = 'admin-uuid-123', string $email = 'ali@ignitlabs.mv'): StaffClaims
{
    return StaffClaims::fromPayload((object) [
        'sub' => $id,
        'identity_id' => $id,
        'name' => 'Ali Waheed',
        'email' => $email,
        'is_staff' => true,
        'aud' => 'hadhiya-fihaara',
        'iss' => 'https://identity.ignitlabs.mv',
        'iat' => time() - 10,
        'exp' => time() + 3590,
        'jti' => 'jti-test',
    ]);
}

beforeEach(function () {
    DB::statement('CREATE TABLE IF NOT EXISTS staff_members (
        id TEXT PRIMARY KEY,
        ib_identity_id TEXT UNIQUE NOT NULL,
        name TEXT,
        email TEXT,
        client_app_id TEXT,
        created_at TEXT,
        updated_at TEXT
    )');
});

afterEach(function () {
    DB::statement('DROP TABLE IF EXISTS staff_members');
});

it('creates a new staff member on first provision', function () {
    $provisioner = new StaffProvisioner;
    $claims = makeStaffClaims();

    $result = $provisioner->provision($claims);

    expect($result['created'])->toBeTrue();

    $row = DB::table('staff_members')->where('ib_identity_id', 'admin-uuid-123')->first();
    expect($row)->not->toBeNull()
        ->and($row->email)->toBe('ali@ignitlabs.mv');
});

it('updates an existing staff member on subsequent provision', function () {
    $provisioner = new StaffProvisioner;
    $claims = makeStaffClaims();

    $provisioner->provision($claims);

    // Now provision again with updated email
    $updatedClaims = makeStaffClaims('admin-uuid-123', 'ali.updated@ignitlabs.mv');
    $result = $provisioner->provision($updatedClaims);

    expect($result['created'])->toBeFalse();

    $row = DB::table('staff_members')->where('ib_identity_id', 'admin-uuid-123')->first();
    expect($row->email)->toBe('ali.updated@ignitlabs.mv');
    expect(DB::table('staff_members')->count())->toBe(1);
});
