<?php

namespace Keboola\AzureKeyVaultClient\Authentication;

use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Psr\Log\LoggerInterface;

class ManagedCredentialsAuthenticator implements AuthenticatorInterface
{

    public function __construct(LoggerInterface $logger, GuzzleClientFactory $clientFactory)
    {
    }

    public function getAuthenticationToken()
    {
        // TODO: Implement getAuthenticationToken() method.
    }
}
