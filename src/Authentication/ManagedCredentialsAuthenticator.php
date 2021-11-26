<?php

namespace Keboola\AzureKeyVaultClient\Authentication;

use GuzzleHttp\Exception\GuzzleException;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Psr\Log\LoggerInterface;

class ManagedCredentialsAuthenticator implements AuthenticatorInterface
{
    /** @var GuzzleClientFactory */
    private $clientFactory;
    /** @var LoggerInterface */
    private $logger;
    /** @var string */
    private $resource;
    /** @var string */
    private $cachedToken;

    const INSTANCE_METADATA_SERVICE_ENDPOINT = 'http://169.254.169.254/';
    const API_VERSION = '2019-11-01';

    public function __construct(GuzzleClientFactory $clientFactory, $resource)
    {
        $this->logger = $clientFactory->getLogger();
        $this->clientFactory = $clientFactory;
        $this->resource = $resource;
    }

    public function getAuthenticationToken()
    {
        if (!empty($this->cachedToken)) {
            return $this->cachedToken;
        }
        try {
            $client = $this->clientFactory->getClient(self::INSTANCE_METADATA_SERVICE_ENDPOINT);
            $response = $client->get(
                sprintf(
                    '/metadata/identity/oauth2/token?api-version=%s&format=text&resource=%s',
                    self::API_VERSION,
                    $this->resource
                ),
                [
                    'headers' => [
                        'Metadata' => 'true'
                    ],
                ]
            );
            $data = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
            if (empty($data['access_token'])) {
                throw new InvalidResponseException('Access token not provided in response: ' . json_encode($data));
            }
            $this->logger->info('Successfully authenticated using instance metadata.');
            $this->cachedToken = (string) $data['access_token'];
            return $this->cachedToken;
        } catch (GuzzleException $e) {
            throw new ClientException('Failed to get authentication token: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    public function checkUsability()
    {
        try {
            $client = $this->clientFactory->getClient(
                self::INSTANCE_METADATA_SERVICE_ENDPOINT,
                ['backoffMaxTries' => 1]
            );
            $client->get(
                sprintf('/metadata?api-version=%s&format=text', self::API_VERSION),
                [
                    'headers' => [
                        'Metadata' => 'true'
                    ],
                ]
            );
        } catch (GuzzleException $e) {
            throw new ClientException('Instance metadata service not available: ' . $e->getMessage(), 0, $e);
        }
    }
}
