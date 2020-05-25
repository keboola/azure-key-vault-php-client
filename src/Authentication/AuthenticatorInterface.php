<?php

namespace Keboola\AzureKeyVaultClient\Authentication;

use Keboola\AzureKeyVaultClient\GuzzleClientFactory;

interface AuthenticatorInterface
{
    public function __construct(GuzzleClientFactory $clientFactory);

    /**
     * @return string
     */
    public function getAuthenticationToken();

    public function checkUsability();
}
