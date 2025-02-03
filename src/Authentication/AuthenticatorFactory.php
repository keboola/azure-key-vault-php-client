<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Authentication;

use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;

class AuthenticatorFactory
{
    public function getAuthenticator(GuzzleClientFactory $clientFactory, string $resource): AuthenticatorInterface
    {
        $authenticator = new ClientCredentialsEnvironmentAuthenticator($clientFactory, $resource);
        try {
            $authenticator->checkUsability();
            return $authenticator;
        } catch (ClientException $e) {
            $clientFactory->getLogger()->debug(
                'ClientCredentialsEnvironmentAuthenticator is not usable: ' . $e->getMessage(),
            );
        }
        /* ManagedCredentialsAuthenticator checkUsability method has poor performance due to slow responses
            from GET /metadata requests */
        return new ManagedCredentialsAuthenticator($clientFactory, $resource);
    }
}
