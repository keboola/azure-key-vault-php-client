<?php

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;

class SecretListResult
{
    /** @var SecretItem[] */
    private $value = [];

    /** @var string */
    private $nextLink;

    /**
     * @param array $data
     */
    public function __construct(array $data)
    {
        if (!isset($data['value']) || !is_array($data['value'])) {
            throw new InvalidResponseException('SecretListResult is invalid: ' . json_encode($data));
        }
        foreach ($data['value'] as $secret) {
            $this->value[] = new SecretItem($secret);
        }
        if (isset($data['nextLink'])) {
            $this->nextLink = (string) $data['nextLink'];
        }
    }

    /**
     * @return SecretItem[]
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @return string
     */
    public function getNextLink()
    {
        return $this->nextLink;
    }
}
