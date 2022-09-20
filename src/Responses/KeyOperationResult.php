<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Base64UrlEncoder;
use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;

class KeyOperationResult
{
    private string $kid;
    private string $value;

    public function __construct(array $data)
    {
        if (!isset($data['kid']) || !isset($data['value'])) {
            throw new InvalidResponseException('KeyOperationResult is invalid: ' . json_encode($data));
        }
        $this->kid = (string) $data['kid'];
        $this->value = (string) $data['value'];
    }

    public function getValue(bool $decode): string
    {
        if ($decode) {
            return Base64UrlEncoder::decode($this->value);
        } else {
            return $this->value;
        }
    }

    public function getKid(): string
    {
        return $this->kid;
    }
}
