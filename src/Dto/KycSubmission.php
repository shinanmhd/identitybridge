<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Dto;

use IgniteLabs\IdentityBridge\Enums\KycSubmissionStatus;

final readonly class KycSubmission
{
    public function __construct(
        public string $id,
        public int $submissionVersion,
        public int $recordVersion,
        public KycSubmissionStatus $status,
        public int $draftStep,
        public ?string $fullName,
        public ?string $dateOfBirth,
        public ?string $nationality,
        public ?string $idType,
        public bool $visaApplicable,
        public array $evidence,
        public ?string $consentPolicyVersion,
        public ?string $submittedAt,
        public ?string $rejectionNote = null,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            (string) $data['id'],
            (int) $data['submission_version'],
            (int) $data['record_version'],
            KycSubmissionStatus::from((string) $data['status']),
            (int) ($data['draft_step'] ?? 1),
            self::nullableString($data['full_name'] ?? null),
            self::nullableString($data['date_of_birth'] ?? null),
            self::nullableString($data['nationality'] ?? null),
            self::nullableString($data['id_type'] ?? null),
            (bool) ($data['visa_applicable'] ?? false),
            array_values($data['evidence'] ?? []),
            self::nullableString($data['consent_policy_version'] ?? null),
            self::nullableString($data['submitted_at'] ?? null),
            self::nullableString($data['rejection_note'] ?? null),
        );
    }

    private static function nullableString(mixed $value): ?string
    {
        return $value === null ? null : (string) $value;
    }
}
