<?php

namespace Keboola\AzureKeyVaultClient\Authentication;

use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Psr\Log\LoggerInterface;

class AuthenticatorFactory
{
    /**
     * @param LoggerInterface $logger
     * @param GuzzleClientFactory $clientFactory
     * @return AuthenticatorInterface
     */
    public function getAuthenticator(LoggerInterface $logger, GuzzleClientFactory $clientFactory)
    {
        if (getenv(ClientCredentialsEnvironmentAuthenticator::ENV_AZURE_TENANT_ID) &&
            getenv(ClientCredentialsEnvironmentAuthenticator::ENV_AZURE_CLIENT_ID) &&
            getenv(ClientCredentialsEnvironmentAuthenticator::ENV_AZURE_CLIENT_SECRET)
        ) {
            return new ClientCredentialsEnvironmentAuthenticator($logger, $clientFactory);
        }
        throw new ClientException('No suitable authentication method found.');
    }
}
