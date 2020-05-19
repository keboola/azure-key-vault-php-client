<?php

namespace Keboola\AzureKeyVaultClient\Tests;

use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Requests\EncryptDecryptRequest;
use PHPUnit\Framework\TestCase;
use Psr\Log\Test\TestLogger;

class ClientFunctionalTest extends TestCase
{
    public function setUp()
    {
        $envs = ['TEST_TENANT_ID', 'TEST_CLIENT_ID', 'TEST_CLIENT_SECRET', 'TEST_KEY_VAULT_URL',
            'TEST_KEY_NAME', 'TEST_KEY_VERSION'];
        foreach ($envs as $env) {
            if (!getenv($env)) {
                throw new \RuntimeException(
                    sprintf('At least one of %s environment variables is empty.', implode(', ', $envs))
                );
            }
        }
        parent::setUp();
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
    }

    public function testEncrypt()
    {
        $logger = new TestLogger();
        $client = new Client($logger,
            new GuzzleClientFactory(),
            new AuthenticatorFactory(),
            getenv('TEST_KEY_VAULT_URL')
        );
        $result = $client->encrypt(
            new EncryptDecryptRequest('RSA1_5', 'test'),
            getenv('TEST_KEY_NAME'),
            getenv('TEST_KEY_VERSION')
        );
        self::assertNotEquals('abc', $result->getValue());
        self::assertGreaterThan(300, strlen($result->getValue()));
        self::assertEquals(
            getenv('TEST_KEY_VAULT_URL') . '/keys/' . getenv('TEST_KEY_NAME') .
                '/' . getenv('TEST_KEY_VERSION'),
            $result->getKid()
        );
    }

    public function testDecrypt()
    {
        $logger = new TestLogger();
        $client = new Client($logger,
            new GuzzleClientFactory(),
            new AuthenticatorFactory(),
            getenv('TEST_KEY_VAULT_URL')
        );
        $result = $client->encrypt(
            new EncryptDecryptRequest('RSA1_5', 'test'),
            getenv('TEST_KEY_NAME'),
            getenv('TEST_KEY_VERSION')
        );
        self::assertNotEquals('abc', $result->getValue());
        $result = $client->decrypt(
            new EncryptDecryptRequest('RSA1_5', $result->getValue()),
            getenv('TEST_KEY_NAME'),
            getenv('TEST_KEY_VERSION')
        );
        self::assertEquals('abc', $result->getValue());
        self::assertEquals(
            getenv('TEST_KEY_VAULT_URL') . '/keys/' . getenv('TEST_KEY_NAME') .
            '/' . getenv('TEST_KEY_VERSION'),
            $result->getKid()
        );
    }

}
