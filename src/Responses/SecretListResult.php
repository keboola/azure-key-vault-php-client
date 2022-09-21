<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;

class SecretListResult
{
    /** @var SecretItem[] */
    private array $value = [];
    private ?string $nextLink = null;

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
    public function getValue(): array
    {
        return $this->value;
    }

    public function getNextLink(): ?string
    {
        return $this->nextLink;
    }
}
