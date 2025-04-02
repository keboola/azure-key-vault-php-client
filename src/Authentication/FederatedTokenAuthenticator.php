<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Authentication;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use JsonException;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Psr\Log\LoggerInterface;

class FederatedTokenAuthenticator implements AuthenticatorInterface
{
    private const ENV_AZURE_TENANT_ID = 'AZURE_TENANT_ID';
    private const ENV_AZURE_CLIENT_ID = 'AZURE_CLIENT_ID';
    private const ENV_AZURE_FEDERATED_TOKEN_FILE = 'AZURE_FEDERATED_TOKEN_FILE';
    private const ENV_AZURE_AUTHORITY_HOST = 'AZURE_AUTHORITY_HOST';

    private const DEFAULT_AZURE_AUTHORITY_HOST = 'https://login.microsoftonline.com';

    // Buffer time in seconds before token expiration to refresh the token
    private const TOKEN_REFRESH_BUFFER = 300; // 5 minutes

    private Client $client;
    private LoggerInterface $logger;

    private string $tenantId;
    private string $clientId;
    private string $federatedTokenFile;
    private string $resource;
    private string $authorityHost;
    private ?string $cachedToken;
    private ?int $tokenExpiresAt;

    public function __construct(GuzzleClientFactory $clientFactory, string $resource, array $options = [])
    {
        $this->logger = $clientFactory->getLogger();
        $this->resource = $resource;

        $this->tenantId = (string) getenv(self::ENV_AZURE_TENANT_ID);
        $this->clientId = (string) getenv(self::ENV_AZURE_CLIENT_ID);
        $this->federatedTokenFile = (string) getenv(self::ENV_AZURE_FEDERATED_TOKEN_FILE);

        // Allow overriding the authority host
        $this->authorityHost = (string) getenv(self::ENV_AZURE_AUTHORITY_HOST);
        if (!$this->authorityHost) {
            $this->authorityHost = self::DEFAULT_AZURE_AUTHORITY_HOST;
            $this->logger->debug(
                self::ENV_AZURE_AUTHORITY_HOST . ' environment variable is not specified, falling back to default.',
            );
        }
        $this->authorityHost = rtrim($this->authorityHost, '/');

        // Initialize client with the base authority host
        $this->client = $clientFactory->getClient($this->authorityHost, $options);
        $this->cachedToken = null;
        $this->tokenExpiresAt = null;
    }

    public function getAuthenticationToken(): string
    {
        if ($this->shouldRefreshToken()) {
            $this->cachedToken = $this->authenticate();
        }

        assert($this->cachedToken !== null);
        return $this->cachedToken;
    }

    public function checkUsability(): void
    {
        $errors = [];
        foreach ([
            self::ENV_AZURE_TENANT_ID,
            self::ENV_AZURE_CLIENT_ID,
            self::ENV_AZURE_FEDERATED_TOKEN_FILE,
        ] as $envVar) {
            if (!getenv($envVar)) {
                $errors[] = sprintf('Environment variable "%s" is not set.', $envVar);
            }
        }
        if ($errors) {
            throw new ClientException(implode(' ', $errors));
        }

        if (!file_exists($this->federatedTokenFile)) {
            throw new ClientException(sprintf('Federated token file "%s" does not exist.', $this->federatedTokenFile));
        }
    }

    private function shouldRefreshToken(): bool
    {
        // If no token or expiration time is set, consider it expired
        if ($this->cachedToken === null || $this->tokenExpiresAt === null) {
            return true;
        }

        // Check if token is expired or will expire within the buffer time
        $currentTime = time();
        return $currentTime >= ($this->tokenExpiresAt - self::TOKEN_REFRESH_BUFFER);
    }

    private function authenticate(): string
    {
        try {
            $federatedToken = @file_get_contents($this->federatedTokenFile);
            if ($federatedToken === false) {
                throw new ClientException(sprintf(
                    'Failed to read federated token from file "%s"',
                    $this->federatedTokenFile,
                ));
            }

            $response = $this->client->post(
                sprintf('%s/%s/oauth2/v2.0/token', $this->authorityHost, $this->tenantId),
                [
                    'form_params' => [
                        'grant_type' => 'client_credentials',
                        'client_id' => $this->clientId,
                        'client_assertion' => $federatedToken,
                        'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                        'scope' => $this->resource . '/.default',
                    ],
                    'headers' => [
                        'Content-type' => 'application/x-www-form-urlencoded',
                    ],
                ],
            );
            $data = (array) json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
            if (empty($data['access_token']) || !is_scalar($data['access_token'])) {
                throw new InvalidResponseException('Access token not provided in response: ' . json_encode($data));
            }

            // Store the token expiration time
            if (isset($data['expires_in']) && is_numeric($data['expires_in'])) {
                $this->tokenExpiresAt = time() + (int) $data['expires_in'];
                $this->logger->debug(sprintf(
                    'Token will expire at %s (in %d seconds)',
                    date('Y-m-d H:i:s', $this->tokenExpiresAt),
                    (int) $data['expires_in'],
                ));
            } else {
                // If no expiration time is provided, set a default of 1 hour
                $this->tokenExpiresAt = time() + 3600;
                $this->logger->debug('No expiration time provided in token response, using default of 1 hour');
            }

            $this->logger->info('Successfully authenticated using federated token.');
            return (string) $data['access_token'];
        } catch (JsonException | GuzzleException $e) {
            throw new ClientException('Failed to get authentication token: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }
}
