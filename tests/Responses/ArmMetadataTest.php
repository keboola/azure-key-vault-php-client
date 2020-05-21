<?php

namespace Keboola\AzureKeyVaultClient\Tests\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Responses\ArmMetadata;
use Keboola\AzureKeyVaultClient\Tests\BaseTest;

class ArmMetadataTest extends BaseTest
{
    public function testValidResponse()
    {
        $metadata = new ArmMetadata($this->getSampleArmMetadata()[0]);
        self::assertEquals('https://login.windows.net/', $metadata->getAuthenticationLoginEndpoint());
        self::assertEquals('vault.azure.net', $metadata->getKeyVaultDns());
    }

    /**
     * @dataProvider invalidResponseProvider
     * @param array $data
     * @param string $expectedMessage
     */
    public function testInvalidValidResponse(array $data, $expectedMessage)
    {
        self::expectException(InvalidResponseException::class);
        self::expectExceptionMessage($expectedMessage);
        new ArmMetadata($data);
    }

    public function invalidResponseProvider()
    {
        return [
            'empty' => [
                [],
                '"name" field not found in API response: []'
            ],
            'missing-name' => [
                [
                    'portal' => 'https://portal.azure.com',
                    'authentication' => [
                        'loginEndpoint' => 'https://login.windows.net/',
                        'audiences' => [
                            'https://management.core.windows.net/',
                            'https://management.azure.com/'
                        ],
                        'tenant' => 'common',
                        'identityProvider' => 'AAD',
                    ],
                    'suffixes' => [
                        'keyVaultDns' => 'vault.azure.net',
                        'storage' => 'core.windows.net',
                    ],
                ],
                '"name" field not found in API response:'
            ],
            'missing-suffixes' => [
                [
                    'portal' => 'https://portal.azure.com',
                    'authentication' => [
                        'loginEndpoint' => 'https://login.windows.net/',
                        'audiences' => [
                            'https://management.core.windows.net/',
                            'https://management.azure.com/'
                        ],
                        'tenant' => 'common',
                        'identityProvider' => 'AAD',
                    ],
                    'media' => 'https://rest.media.azure.net',
                    'name' => 'AzureCloud',
                ],
                '"suffixes.keyVaultDns" field not found in API response:'
            ],
            'missing-keyVaultDns' => [
                [
                    'portal' => 'https://portal.azure.com',
                    'authentication' => [
                        'loginEndpoint' => 'https://login.windows.net/',
                        'audiences' => [
                            'https://management.core.windows.net/',
                            'https://management.azure.com/'
                        ],
                        'tenant' => 'common',
                        'identityProvider' => 'AAD',
                    ],
                    'media' => 'https://rest.media.azure.net',
                    'name' => 'AzureCloud',
                    'suffixes' => [
                        'storage' => 'core.windows.net',
                    ],
                ],
                '"suffixes.keyVaultDns" field not found in API response:'
            ],
            'missing-authentication' => [
                [
                    'portal' => 'https://portal.azure.com',
                    'media' => 'https://rest.media.azure.net',
                    'name' => 'AzureCloud',
                    'suffixes' => [
                        'keyVaultDns' => 'vault.azure.net',
                        'storage' => 'core.windows.net',
                    ],
                ],
                '"authentication.loginEndpoint" field not found in API response:'
            ],
            'missing-loginEndpoint' => [
                [
                    'portal' => 'https://portal.azure.com',
                    'authentication' => [
                        'audiences' => [
                            'https://management.core.windows.net/',
                            'https://management.azure.com/'
                        ],
                        'tenant' => 'common',
                        'identityProvider' => 'AAD',
                    ],
                    'media' => 'https://rest.media.azure.net',
                    'name' => 'AzureCloud',
                    'suffixes' => [
                        'keyVaultDns' => 'vault.azure.net',
                        'storage' => 'core.windows.net',
                    ],
                ],
                '"authentication.loginEndpoint" field not found in API response:'
            ],
        ];
    }
}
