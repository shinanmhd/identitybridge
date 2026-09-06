<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Exceptions;

final class AccountDeletionException extends IdentityBridgeException
{
    public function __construct(
        public readonly string $category,
        public readonly string $codeName,
        public readonly ?int $status,
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

    public static function transportFailure(): self
    {
        return new self('server', 'service_unavailable', null);
    }

    public static function invalidResponse(int $status): self
    {
        return new self('protocol', 'invalid_response', $status);
    }

    public function __toString(): string
    {
        return self::class.': '.$this->getMessage();
    }

    /** @return array{category: string, code_name: string, status: int|null, retry_after: int|null} */
    public function __serialize(): array
    {
        return [
            'category' => $this->category,
            'code_name' => $this->codeName,
            'status' => $this->status,
            'retry_after' => $this->retryAfter,
        ];
    }
}
