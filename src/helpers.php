<?php

use IgniteLabs\IdentityBridge\Identity\IdentityClaims;

if (! function_exists('identity')) {
    /**
     * Get the IdentityClaims for the current request.
     *
     * @throws RuntimeException if called outside of the auth:identity guard context
     */
    function identity(): IdentityClaims
    {
        $claims = app('request')->attributes->get('identity_claims');

        if ($claims === null) {
            throw new RuntimeException(
                'identity() called outside of auth:identity guard context. '.
                'Ensure the auth:identity guard has run before calling identity().'
            );
        }

        return $claims;
    }
}
