<?php

namespace Keboola\AzureKeyVaultClient\Authentication;

use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Psr\Log\LoggerInterface;

interface AuthenticatorInterface
{
    public function __construct(LoggerInterface $logger, GuzzleClientFactory $clientFactory);

    /**
     * @return string
     */
    public function getAuthenticationToken();
}
