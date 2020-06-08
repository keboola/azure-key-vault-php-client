<?php

namespace Keboola\AzureKeyVaultClient\Requests;

class SetSecretRequest
{
    /** @var SecretAttributes */
    private $attributes;

    /** @var string */
    private $contentType;

    /** @var string */
    private $tags;

    /** @var string */
    private $value;

    /**
     * @param string $value
     * @param SecretAttributes $attributes
     * @param string $contentType
     * @param array $tags
     */
    public function __construct($value, SecretAttributes $attributes, $contentType = null, $tags = null)
    {
        $this->value = $value;
        $this->attributes = $attributes;
        $this->contentType = $contentType;
        $this->tags = $tags;
    }

    /**
     * @return array
     */
    public function getArray()
    {
        $result = [
            'value' => (string) $this->value,
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
