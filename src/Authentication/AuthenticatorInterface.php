<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Authentication;

use Keboola\AzureKeyVaultClient\GuzzleClientFactory;

interface AuthenticatorInterface
{
    public function __construct(GuzzleClientFactory $clientFactory, string $resource);

    public function getAuthenticationToken(): string;

    public function checkUsability(): void;
}
