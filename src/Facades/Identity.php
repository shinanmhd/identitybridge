<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static string getServiceToken()
 * @method static array getIdentity(string $identityId)
 * @method static bool revokeToken(string $jti)
 * @method static string refreshServiceToken()
 *
 * @see \IgniteLabs\IdentityBridge\Client\IdentityBridgeClient
 */
class Identity extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'identity-bridge';
    }
}
