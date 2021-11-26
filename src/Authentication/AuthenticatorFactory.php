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
    public function getAuthenticator(GuzzleClientFactory $clientFactory, $resource)
    {
        $authenticator = new ClientCredentialsEnvironmentAuthenticator($clientFactory, $resource);
        try {
            $authenticator->checkUsability();
            return $authenticator;
        } catch (ClientException $e) {
            $clientFactory->getLogger()->debug(
                'ClientCredentialsEnvironmentAuthenticator is not usable: ' . $e->getMessage()
            );
        }
        /* ManagedCredentialsAuthenticator checkUsability method has poor performance due to slow responses
            from GET /metadata requests */
        return new ManagedCredentialsAuthenticator($clientFactory, $resource);
    }
}
