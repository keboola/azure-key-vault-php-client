<?php

namespace Keboola\AzureKeyVaultClient\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;

class ArmMetadata
{
    /** @var string */
    private $loginEndpoint;
    /** @var string */
    private $keyVaultDns;
    /** @var string */
    private $name;

    public function __construct(array $data)
    {
        if (!empty($data['name'])) {
            $this->name = (string) $data['name'];
        } else {
            throw new InvalidResponseException(
                '"name" field not found in API response: ' . \GuzzleHttp\json_encode($data)
            );
        }
        if (!empty($data['suffixes']['keyVaultDns'])) {
            $this->keyVaultDns = (string) $data['suffixes']['keyVaultDns'];
        } else {
            throw new InvalidResponseException(
                '"suffixes.keyVaultDns" field not found in API response: ' . \GuzzleHttp\json_encode($data)
            );
        }
        if (!empty($data['authentication']['loginEndpoint'])) {
            $this->loginEndpoint = (string) $data['authentication']['loginEndpoint'];
        } else {
            throw new InvalidResponseException(
                '"authentication.loginEndpoint" field not found in API response: ' . \GuzzleHttp\json_encode($data)
            );
        }
    }

    /**
     * @return string
     */
    public function getAuthenticationLoginEndpoint()
    {
        return $this->loginEndpoint;
    }

    /**
     * @return string
     */
    public function getKeyVaultDns()
    {
        return $this->keyVaultDns;
    }
}
