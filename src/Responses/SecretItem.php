<?php

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Requests\SecretAttributes;

class SecretItem
{
    /** @var SecretAttributes */
    protected $attributes;

    /** @var string */
    protected $contentType;

    /** @var string */
    protected $id;

    /** @var bool */
    protected $managed;

    /** @var array */
    protected $tags;

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

    protected function validateData(array $data)
    {
        if (!isset($data['id']) || !isset($data['attributes'])) {
            throw new InvalidResponseException('SecretItem is invalid: ' . json_encode($data));
        }
    }

    /**
     * @return SecretAttributes
     */
    public function getAttributes()
    {
        return $this->attributes;
    }

    /**
     * @return string
     */
    public function getContentType()
    {
        return $this->contentType;
    }

    /**
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * @return bool
     */
    public function isManaged()
    {
        return $this->managed;
    }

    /**
     * @return array
     */
    public function getTags()
    {
        return $this->tags;
    }

    /**
     * @return array
     */
    protected function getIdParts()
    {
        $parts = explode('/', $this->id);
        if (count($parts) < 3) {
            throw new InvalidResponseException(sprintf('Invalid secret ID format "%s".', $this->id));
        }
        return $parts;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return (string) $this->getIdParts()[count($this->getIdParts()) - 1];
    }
}
