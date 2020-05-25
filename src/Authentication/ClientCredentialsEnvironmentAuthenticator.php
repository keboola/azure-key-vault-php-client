<?php

namespace Keboola\AzureKeyVaultClient\Authentication;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Psr7\Request;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Responses\ArmMetadata;
use Psr\Log\LoggerInterface;

class ClientCredentialsEnvironmentAuthenticator implements AuthenticatorInterface
{
    const ENV_AZURE_AD_RESOURCE = 'AZURE_AD_RESOURCE';
    const ENV_AZURE_ENVIRONMENT = 'AZURE_ENVIRONMENT';
    const ENV_AZURE_TENANT_ID = 'AZURE_TENANT_ID';
    const ENV_AZURE_CLIENT_ID = 'AZURE_CLIENT_ID';
    const ENV_AZURE_CLIENT_SECRET = 'AZURE_CLIENT_SECRET';

    const DEFAULT_ARM_URL = 'https://management.azure.com/metadata/endpoints?api-version=2020-01-01';
    const DEFAULT_PUBLIC_CLOUD_NAME = 'AzureCloud';

    /** @var Client */
    private $client;
    /** @var LoggerInterface */
    private $logger;

    /** @var string */
    private $tenantId;
    /** @var string */
    private $clientId;
    /** @var string */
    private $clientSecret;

    /** @var string */
    private $armUrl;
    /** @var string */
    private $cloudName;

    public function __construct(GuzzleClientFactory $clientFactory)
    {
        $this->logger = $clientFactory->getLogger();
        $this->armUrl = (string)getenv(self::ENV_AZURE_AD_RESOURCE);
        if (!$this->armUrl) {
            $this->armUrl = self::DEFAULT_ARM_URL;
            $this->logger->debug(
                self::ENV_AZURE_AD_RESOURCE . ' environment variable is not specified, falling back to default.'
            );
        }
        $this->cloudName = (string)getenv(self::ENV_AZURE_ENVIRONMENT);
        if (!$this->cloudName) {
            $this->cloudName = self::DEFAULT_PUBLIC_CLOUD_NAME;
            $this->logger->debug(
                self::ENV_AZURE_ENVIRONMENT . ' environment variable is not specified, falling back to default.'
            );
        }

        $this->tenantId = (string)getenv(self::ENV_AZURE_TENANT_ID);
        $this->clientId = (string)getenv(self::ENV_AZURE_CLIENT_ID);
        $this->clientSecret = (string)getenv(self::ENV_AZURE_CLIENT_SECRET);
        $this->client = $clientFactory->getClient($this->armUrl);
    }

    private function processInstanceMetadata(array $metadataArray, $cloudName)
    {
        $cloud = null;
        foreach ($metadataArray as $item) {
            if (!empty($item['name']) && ($item['name'] === $cloudName)) {
                $cloud = $item;
            }
        }
        if (!$cloud) {
            throw new ClientException(
                sprintf('Cloud "%s" not found in instance metadata: ' . json_encode($metadataArray), $cloudName)
            );
        }
        return new ArmMetadata($cloud);
    }

    public function getAuthenticationToken()
    {
        $metadata = $this->getMetadata($this->armUrl);
        $metadata = $this->processInstanceMetadata($metadata, $this->cloudName);
        $keyVaultUrl = 'https://' . $metadata->getKeyVaultDns();
        return $this->authenticate($metadata->getAuthenticationLoginEndpoint(), $keyVaultUrl);
    }

    public function checkUsability()
    {
        $errors = [];
        foreach ([self::ENV_AZURE_TENANT_ID, self::ENV_AZURE_CLIENT_ID, self::ENV_AZURE_CLIENT_SECRET] as $envVar) {
            if (!getenv($envVar)) {
                $errors[] = sprintf('Environment variable "%s" is not set.', $envVar);
            }
        }
        if ($errors) {
            throw new ClientException(implode(' ', $errors));
        }
    }

    private function getMetadata($armUrl)
    {
        try {
            $request = new Request('GET', $armUrl);
            $response = $this->client->send($request);
            $metadata = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
            if (!is_array($metadata)) {
                throw new InvalidResponseException(
                    'Invalid metadata contents: ' . \GuzzleHttp\json_encode($metadata)
                );
            }
            return $metadata;
        } catch (GuzzleException $e) {
            throw new ClientException('Failed to get instance metadata: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    private function authenticate($authUrl, $resource)
    {
        try {
            $response = $this->client->post(
                sprintf('%s%s/oauth2/token', $authUrl, $this->tenantId),
                [
                    'form_params' => [
                        'grant_type' => 'client_credentials',
                        'client_id' => $this->clientId,
                        'client_secret' => $this->clientSecret,
                        'resource' => $resource,
                    ],
                    'headers' => [
                        'Content-type' => 'application/x-www-form-urlencoded',
                    ],
                ]
            );
            $data = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
            if (empty($data['access_token'])) {
                throw new InvalidResponseException('Access token not provided in response: ' . json_encode($data));
            }
            $this->logger->info('Successfully authenticated using client credentials.');
            return (string) $data['access_token'];
        } catch (GuzzleException $e) {
            throw new ClientException('Failed to get authentication token: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }
}
