<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Requests;

class SetSecretRequest
{
    private SecretAttributes $attributes;
    private ?string $contentType;
    private ?array $tags;
    private string $value;

    public function __construct(
        string $value,
        SecretAttributes $attributes,
        ?string $contentType = null,
        ?array $tags = null,
    ) {
        $this->value = $value;
        $this->attributes = $attributes;
        $this->contentType = $contentType;
        $this->tags = $tags;
    }

    public function getArray(): array
    {
        $result = [
            'value' => $this->value,
        ];
        if ($this->attributes->getArray()) {
            $result['attributes'] = $this->attributes->getArray();
        }
        if (!is_null($this->contentType)) {
            $result['contentType'] = (string) $this->contentType;
        }
        if (!is_null($this->tags)) {
            $result['tags'] = (array) $this->tags;
        }
        return $result;
    }
}
