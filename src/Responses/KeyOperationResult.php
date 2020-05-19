<?php

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;

class KeyOperationResult
{
    /** @var string */
    private $kid;
    /** @var string */
    private $value;

    /**
     * @param array $data
     */
    public function __construct(array $data)
    {
        if (!isset($data['kid']) || !isset($data['value'])) {
            throw new InvalidResponseException('KeyOperationResult is invalid: ' . json_encode($data));
        }
        $this->kid = (string) $data['kid'];
        $this->value = (string) $data['value'];
    }

    /**
     * @return string
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @return string
     */
    public function getKid()
    {
        return $this->kid;
    }
}
