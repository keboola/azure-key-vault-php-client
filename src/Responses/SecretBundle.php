<?php

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;

class SecretBundle extends SecretItem
{
    /** @var string */
    protected $kid;

    /** @var string */
    protected $value;

    /**
     * @param array $data
     */
    public function __construct(array $data)
    {
        parent::__construct($data);
        if (isset($data['value'])) {
            $this->value = (string)$data['value'];
        }
        if (isset($data['kid'])) {
            $this->kid = (string) $data['kid'];
        }
    }

    protected function validateData(array $data)
    {
        if (!isset($data['value'])) {
            throw new InvalidResponseException('SecretBundle is invalid: ' . json_encode($data));
        }
        parent::validateData($data);
    }

    /**
     * @return string
     */
    public function getKid()
    {
        return $this->kid;
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
    protected function getIdParts()
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
