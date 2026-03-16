<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class VerifyWebhookSignature
{
    public function handle(Request $request, Closure $next): Response
    {
        $rawBody = $request->getContent();
        $header  = $request->header('X-Identity-Signature');

        if (! $header) {
            return response()->json(['error' => 'Invalid signature'], 401);
        }

        $rawSecret    = config('identity-bridge.webhook_secret');
        $hashedSecret = hash('sha256', $rawSecret);
        $expected     = hash_hmac('sha256', $rawBody, $hashedSecret);

        $provided = str_starts_with($header, 'sha256=')
            ? substr($header, 7)
            : $header;

        if (! hash_equals($expected, $provided)) {
            return response()->json(['error' => 'Invalid signature'], 401);
        }

        return $next($request);
    }
}
