<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Exceptions;

final class AccountDeletionException extends IdentityBridgeException
{
    public function __construct(
        public readonly string $category,
        public readonly string $codeName,
        public readonly int $status,
        public readonly ?int $retryAfter = null,
    ) {
        parent::__construct('Identity Bridge account deletion request failed.');
    }

    public function isRetryable(): bool
    {
        return $this->category === 'rate_limited' || $this->category === 'server';
    }

    public function isNotFound(): bool
    {
        return $this->category === 'not_found';
    }
}
