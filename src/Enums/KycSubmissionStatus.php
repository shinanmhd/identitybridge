<?php

declare(strict_types=1);

namespace IgniteLabs\IdentityBridge\Enums;

enum KycSubmissionStatus: string
{
    case Draft = 'draft';
    case Pending = 'pending';
    case Syncing = 'syncing';
    case Verified = 'verified';
    case Rejected = 'rejected';
}
