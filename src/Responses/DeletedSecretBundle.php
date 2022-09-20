<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;

class DeletedSecretBundle extends SecretBundle
{
    protected int $deletedDate;
    protected string $recoveryId;
    protected int $scheduledPurgeDate;

    public function __construct(array $data)
    {
        parent::__construct($data);
        if (isset($data['deletedDate'])) {
            $this->deletedDate = (int) $data['deletedDate'];
        }
        if (isset($data['recoveryId'])) {
            $this->recoveryId = (string) $data['recoveryId'];
        }
        if (isset($data['scheduledPurgeDate'])) {
            $this->scheduledPurgeDate = (int) $data['scheduledPurgeDate'];
        }
    }

    protected function validateData(array $data): void
    {
        if (!isset($data['id'])) {
            throw new InvalidResponseException('DeletedSecretBundle is invalid: ' . json_encode($data));
        }
    }

    public function getDeletedDate(): int
    {
        return $this->deletedDate;
    }

    public function getRecoveryId(): string
    {
        return $this->recoveryId;
    }

    public function getScheduledPurgeDate(): int
    {
        return $this->scheduledPurgeDate;
    }
}
