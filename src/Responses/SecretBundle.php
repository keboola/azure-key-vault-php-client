<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;

class SecretBundle extends SecretItem
{
    protected string $kid;
    protected string $value;

    public function __construct(array $data)
    {
        parent::__construct($data);
        if (isset($data['value'])) {
            $this->value = (string) $data['value'];
        }
        if (isset($data['kid'])) {
            $this->kid = (string) $data['kid'];
        }
    }

    protected function validateData(array $data): void
    {
        if (!isset($data['value'])) {
            throw new InvalidResponseException('SecretBundle is invalid: ' . json_encode($data));
        }
        parent::validateData($data);
    }

    public function getKid(): string
    {
        return $this->kid;
    }

    public function getValue(): string
    {
        return $this->value;
    }

    protected function getIdParts(): array
    {
        $parts = explode('/', $this->id);
        if (count($parts) < 4) {
            throw new InvalidResponseException(sprintf('Invalid secret ID format "%s".', $this->id));
        }
        return $parts;
    }

    public function getName(): string
    {
        return (string) $this->getIdParts()[count($this->getIdParts()) - 2];
    }

    public function getVersion(): string
    {
        return (string) $this->getIdParts()[count($this->getIdParts()) - 1];
    }
}
