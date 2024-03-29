<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests\Responses;

use Generator;
use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Responses\ArmMetadata;
use Keboola\AzureKeyVaultClient\Tests\BaseTest;

class ArmMetadataTest extends BaseTest
{
    public function testValidResponse(): void
    {
        $metadata = new ArmMetadata($this->getSampleArmMetadata()[0]);
        self::assertEquals('https://login.windows.net/', $metadata->getAuthenticationLoginEndpoint());
    }

    /**
     * @dataProvider invalidResponseProvider
     */
    public function testInvalidValidResponse(array $data, string $expectedMessage): void
    {
        self::expectException(InvalidResponseException::class);
        self::expectExceptionMessage($expectedMessage);
        new ArmMetadata($data);
    }

    public function invalidResponseProvider(): Generator
    {
        yield 'empty' => [
            [],
            '"name" field not found in API response: []',
        ];
        yield 'missing-name' => [
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
                'suffixes' => [
                    'keyVaultDns' => 'vault.azure.net',
                    'storage' => 'core.windows.net',
                ],
            ],
            '"name" field not found in API response:',
        ];
        yield 'missing-suffixes' => [
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
                'name' => 'AzureCloud',
            ],
            '"suffixes.keyVaultDns" field not found in API response:',
        ];
        yield 'missing-keyVaultDns' => [
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
                'name' => 'AzureCloud',
                'suffixes' => [
                    'storage' => 'core.windows.net',
                ],
            ],
            '"suffixes.keyVaultDns" field not found in API response:',
        ];
        yield 'missing-authentication' => [
            [
                'portal' => 'https://portal.azure.com',
                'media' => 'https://rest.media.azure.net',
                'name' => 'AzureCloud',
                'suffixes' => [
                    'keyVaultDns' => 'vault.azure.net',
                    'storage' => 'core.windows.net',
                ],
            ],
            '"authentication.loginEndpoint" field not found in API response:',
        ];
        yield 'missing-loginEndpoint' => [
            [
                'portal' => 'https://portal.azure.com',
                'authentication' => [
                    'audiences' => [
                        'https://management.core.windows.net/',
                        'https://management.azure.com/',
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
            '"authentication.loginEndpoint" field not found in API response:',
        ];
    }
}
