<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Dto;

use IgniteLabs\IdentityBridge\Enums\KycSubmissionStatus;

final readonly class KycReviewItem
{
    public function __construct(
        public string $id,
        public string $identityId,
        public int $submissionVersion,
        public int $recordVersion,
        public KycSubmissionStatus $status,
        public ?string $fullName,
        public ?string $dateOfBirth,
        public ?string $nationality,
        public ?string $idType,
        public string $maskedDocumentNumber,
        public ?string $reviewerActorId,
        public ?string $reviewerServiceId,
        public ?string $submittedAt,
        public ?string $decidedAt,
        public ?string $rejectionNote,
        public array $evidence,
    ) {}

    public static function fromArray(array $data): self
    {
        $nullable = static fn (mixed $value): ?string => $value === null ? null : (string) $value;

        return new self(
            (string) $data['id'],
            (string) $data['identity_id'],
            (int) $data['submission_version'],
            (int) $data['record_version'],
            KycSubmissionStatus::from((string) $data['status']),
            $nullable($data['full_name'] ?? null),
            $nullable($data['date_of_birth'] ?? null),
            $nullable($data['nationality'] ?? null),
            $nullable($data['id_type'] ?? null),
            (string) ($data['masked_document_number'] ?? $data['masked_document'] ?? ''),
            $nullable($data['reviewer_actor_id'] ?? null),
            $nullable($data['reviewer_service_id'] ?? null),
            $nullable($data['submitted_at'] ?? null),
            $nullable($data['decided_at'] ?? null),
            $nullable($data['rejection_note'] ?? null),
            array_values($data['evidence'] ?? []),
        );
    }
}
