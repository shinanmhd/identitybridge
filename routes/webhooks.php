<?php

use IgniteLabs\IdentityBridge\Http\Controllers\WebhookController;
use Illuminate\Support\Facades\Route;

Route::post(
    config('identity-bridge.webhook_path', 'webhooks/identity'),
    [WebhookController::class, 'handle'],
)->middleware(['verify.webhook'])->name('identity-bridge.webhook');
