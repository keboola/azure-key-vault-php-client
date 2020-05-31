<?php

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;

class DeletedSecretBundle extends SecretBundle
{
    /** @var int */
    protected $deletedDate;

    /** @var string */
    protected $recoveryId;

    /** @var int */
    protected $scheduledPurgeDate;

    /**
     * @param array $data
     */
    public function __construct(array $data)
    {
        parent::__construct($data);
        if (isset($data['deletedDate'])) {
            $this->deletedDate = (int)$data['deletedDate'];
        }
        if (isset($data['recoveryId'])) {
            $this->recoveryId = (string)$data['recoveryId'];
        }
        if (isset($data['scheduledPurgeDate'])) {
            $this->scheduledPurgeDate = (int)$data['scheduledPurgeDate'];
        }
    }

    protected function validateData(array $data)
    {
        if (!isset($data['id'])) {
            throw new InvalidResponseException('DeletedSecretBundle is invalid: ' . json_encode($data));
        }
    }

    /**
     * @return int
     */
    public function getDeletedDate()
    {
        return $this->deletedDate;
    }

    /**
     * @return string
     */
    public function getRecoveryId()
    {
        return $this->recoveryId;
    }

    /**
     * @return int
     */
    public function getScheduledPurgeDate()
    {
        return $this->scheduledPurgeDate;
    }
}
