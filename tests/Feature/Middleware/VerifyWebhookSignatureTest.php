<?php

use IgniteLabs\IdentityBridge\Http\Middleware\VerifyWebhookSignature;
use IgniteLabs\IdentityBridge\Tests\Fixtures\KeyFixture;
use Illuminate\Http\Request;

function webhookSig(string $body, string $rawSecret): string
{
    return 'sha256=' . hash_hmac('sha256', $body, hash('sha256', $rawSecret));
}

it('valid signature passes through', function () {
    $body   = '{"event":"user.created"}';
    $secret = config('identity-bridge.webhook_secret');
    $sig    = webhookSig($body, $secret);

    $request = Request::create('/webhook', 'POST', [], [], [], [], $body);
    $request->headers->set('X-Identity-Signature', $sig);

    $middleware = new VerifyWebhookSignature();
    $response   = $middleware->handle($request, fn ($r) => response()->json(['ok' => true]));

    expect($response->getStatusCode())->toBe(200);
});

it('wrong signature returns 401', function () {
    $body = '{"event":"user.created"}';

    $request = Request::create('/webhook', 'POST', [], [], [], [], $body);
    $request->headers->set('X-Identity-Signature', 'sha256=deadbeefdeadbeef');

    $middleware = new VerifyWebhookSignature();
    $response   = $middleware->handle($request, fn ($r) => response()->json(['ok' => true]));

    expect($response->getStatusCode())->toBe(401)
        ->and($response->getData(true)['error'])->toBe('Invalid signature');
});

it('missing X-Identity-Signature header returns 401', function () {
    $body = '{"event":"user.created"}';

    $request    = Request::create('/webhook', 'POST', [], [], [], [], $body);
    $middleware = new VerifyWebhookSignature();
    $response   = $middleware->handle($request, fn ($r) => response()->json(['ok' => true]));

    expect($response->getStatusCode())->toBe(401)
        ->and($response->getData(true)['error'])->toBe('Invalid signature');
});

it('empty body with valid signature passes', function () {
    $body   = '';
    $secret = config('identity-bridge.webhook_secret');
    $sig    = webhookSig($body, $secret);

    $request = Request::create('/webhook', 'POST', [], [], [], [], $body);
    $request->headers->set('X-Identity-Signature', $sig);

    $middleware = new VerifyWebhookSignature();
    $response   = $middleware->handle($request, fn ($r) => response()->json(['ok' => true]));

    expect($response->getStatusCode())->toBe(200);
});

it('uses pre-hashed secret as HMAC key, not raw secret directly', function () {
    $body      = '{"event":"user.created"}';
    $rawSecret = config('identity-bridge.webhook_secret');

    // Correct: hash(secret) used as HMAC key
    $correctSig = webhookSig($body, $rawSecret);

    // Wrong: raw secret used as HMAC key (no pre-hashing)
    $wrongSig = 'sha256=' . hash_hmac('sha256', $body, $rawSecret);

    $middleware = new VerifyWebhookSignature();

    $requestOk = Request::create('/webhook', 'POST', [], [], [], [], $body);
    $requestOk->headers->set('X-Identity-Signature', $correctSig);
    expect($middleware->handle($requestOk, fn ($r) => response('ok'))->getStatusCode())->toBe(200);

    $requestBad = Request::create('/webhook', 'POST', [], [], [], [], $body);
    $requestBad->headers->set('X-Identity-Signature', $wrongSig);
    expect($middleware->handle($requestBad, fn ($r) => response('ok'))->getStatusCode())->toBe(401);
});

it('tampered body is rejected even with original signature', function () {
    $original = '{"event":"user.created"}';
    $tampered = '{"event":"account.deleted"}';
    $secret   = config('identity-bridge.webhook_secret');

    $sig = webhookSig($original, $secret); // signed with original

    $request = Request::create('/webhook', 'POST', [], [], [], [], $tampered);
    $request->headers->set('X-Identity-Signature', $sig);

    $middleware = new VerifyWebhookSignature();
    $response   = $middleware->handle($request, fn ($r) => response('ok'));

    expect($response->getStatusCode())->toBe(401);
});
