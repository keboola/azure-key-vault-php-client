<?php

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Base64UrlEncoder;
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
     * @param bool $decode
     * @return string
     */
    public function getValue($decode)
    {
        if ($decode) {
            return Base64UrlEncoder::decode($this->value);
        } else {
            return $this->value;
        }
    }

    /**
     * @return string
     */
    public function getKid()
    {
        return $this->kid;
    }
}
