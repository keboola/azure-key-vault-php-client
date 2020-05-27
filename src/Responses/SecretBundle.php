<?php

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Base64UrlEncoder;
use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Requests\SecretAttributes;

class SecretBundle
{
    /** @var SecretAttributes */
    private $attributes;

    /** @var string */
    private $contentType;

    /** @var string */
    private $id;

    /** @var string */
    private $kid;

    /** @var bool */
    private $managed;

    /** @var array */
    private $tags;

    /** @var string */
    private $value;

    /**
     * @param array $data
     */
    public function __construct(array $data)
    {
        if (!isset($data['id']) || !isset($data['value']) || !isset($data['attributes'])) {
            throw new InvalidResponseException('SecretBundle is invalid: ' . json_encode($data));
        }
        $this->attributes = SecretAttributes::fromArray($data['attributes']);
        $this->id = (string) $data['id'];
        $this->value = (string) $data['value'];

        if (!isset($data['kid'])) {
            $this->kid = null;
        } else {
            $this->kid = (string) $data['kid'];
        }

        if (!isset($data['contentType'])) {
            $this->contentType = null;
        } else {
            $this->contentType = (string) $data['contentType'];
        }
        if (!isset($data['managed'])) {
            $this->managed = null;
        } else {
            $this->managed = (bool) $data['managed'];
        }
        if (!isset($data['tags'])) {
            $this->tags = [];
        } else {
            $this->tags = (array) $data['tags'];
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
     * @return string
     */
    public function getKid()
    {
        return $this->kid;
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
     * @return string
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @return array
     */
    private function getIdParts()
    {
        $parts = explode('/', $this->id);
        if (count($parts) < 4) {
            throw new InvalidResponseException(sprintf('Invalid secret ID format "%s".', $this->id));
        }
        return $parts;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return (string) $this->getIdParts()[count($this->getIdParts()) - 2];
    }

    /**
     * @return string
     */
    public function getVersion()
    {
        return (string) $this->getIdParts()[count($this->getIdParts()) - 1];
    }
}
