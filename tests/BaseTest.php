<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests;

use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

abstract class BaseTest extends TestCase
{
    public function setUp(): void
    {
        parent::setUp();
        putenv('AZURE_TENANT_ID=tenant123');
        putenv('AZURE_CLIENT_ID=client123');
        putenv('AZURE_CLIENT_SECRET=secret123');
        putenv('AZURE_AD_RESOURCE=');
        putenv('AZURE_ENVIRONMENT=');
    }

    protected function getSampleArmMetadata(): array
    {
        return [
            [
                'portal' => 'https://portal.azure.com',
                'authentication' => [
                    'loginEndpoint' => 'https://login.windows.net/',
                    'audiences' => [
                        'https://management.core.windows.net/',
                        'https://management.azure.com/',
                    ],
                    'tenant' => 'common',
                    'identityProvider' => 'AAD',
                ],
                'media' => 'https://rest.media.azure.net',
                'graphAudience' => 'https://graph.windows.net/',
                'graph' => 'https://graph.windows.net/',
                'name' => 'AzureCloud',
                'suffixes' => [
                    'azureDataLakeStoreFileSystem' => 'azuredatalakestore.net',
                    'acrLoginServer' => 'azurecr.io',
                    'sqlServerHostname' => 'database.windows.net',
                    'azureDataLakeAnalyticsCatalogAndJob' => 'azuredatalakeanalytics.net',
                    'keyVaultDns' => 'vault.azure.net',
                    'storage' => 'core.windows.net',
                    'azureFrontDoorEndpointSuffix' => 'azurefd.net',
                ],
                'batch' => 'https://batch.core.windows.net/',
                'resourceManager' => 'https://management.azure.com/',
                // phpcs:ignore Generic.Files.LineLength
                'vmImageAliasDoc' => 'https://raw.githubusercontent.com/Azure/azure-rest-api-specs/master/arm-compute/quickstart-templates/aliases.json',
                'activeDirectoryDataLake' => 'https://datalake.azure.net/',
                'sqlManagement' => 'https://management.core.windows.net:8443/',
                'gallery' => 'https://gallery.azure.com/',
            ],
        ];
    }

    protected function getMockAuthResponses(): array
    {
        return [
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                (string) json_encode($this->getSampleArmMetadata()),
            ),
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                '{
                    "token_type": "Bearer",
                    "expires_in": "3599",
                    "ext_expires_in": "3599",
                    "expires_on": "1589810452",
                    "not_before": "1589806552",
                    "resource": "https://vault.azure.net",
                    "access_token": "ey....ey"
                }',
            ),
        ];
    }
}
