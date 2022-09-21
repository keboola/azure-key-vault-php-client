<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Requests\SecretAttributes;

class SecretItem
{
    protected SecretAttributes $attributes;
    protected string $contentType;
    protected string $id;
    protected bool $managed;
    protected array $tags;

    /**
     * @param array $data
     */
    public function __construct(array $data)
    {
        $this->validateData($data);
        $this->attributes = SecretAttributes::fromArray($data['attributes']);
        $this->id = (string) $data['id'];

        if (isset($data['contentType'])) {
            $this->contentType = (string) $data['contentType'];
        }
        if (isset($data['managed'])) {
            $this->managed = (bool) $data['managed'];
        }
        if (isset($data['tags'])) {
            $this->tags = (array) $data['tags'];
        }
    }

    protected function validateData(array $data): void
    {
        if (!isset($data['id']) || !isset($data['attributes'])) {
            throw new InvalidResponseException('SecretItem is invalid: ' . json_encode($data));
        }
    }

    public function getAttributes(): SecretAttributes
    {
        return $this->attributes;
    }

    public function getContentType(): string
    {
        return $this->contentType;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function isManaged(): bool
    {
        return $this->managed;
    }

    public function getTags(): array
    {
        return $this->tags;
    }

    protected function getIdParts(): array
    {
        $parts = explode('/', $this->id);
        if (count($parts) < 3) {
            throw new InvalidResponseException(sprintf('Invalid secret ID format "%s".', $this->id));
        }
        return $parts;
    }

    public function getName(): string
    {
        return (string) $this->getIdParts()[count($this->getIdParts()) - 1];
    }
}
