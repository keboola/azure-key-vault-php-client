<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests;

use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Requests\DecryptRequest;
use Keboola\AzureKeyVaultClient\Requests\EncryptDecryptRequest;
use Keboola\AzureKeyVaultClient\Requests\EncryptRequest;
use Keboola\AzureKeyVaultClient\Requests\SecretAttributes;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Psr\Log\Test\TestLogger;
use RuntimeException;

class ClientFunctionalTest extends TestCase
{
    public function setUp(): void
    {
        $envs = ['TEST_TENANT_ID', 'TEST_CLIENT_ID', 'TEST_CLIENT_SECRET', 'TEST_KEY_VAULT_URL',
            'TEST_KEY_NAME', 'TEST_KEY_VERSION'];
        foreach ($envs as $env) {
            if (!getenv($env)) {
                throw new RuntimeException(
                    sprintf('At least one of %s environment variables is empty.', implode(', ', $envs)),
                );
            }
        }
        parent::setUp();
        putenv('AZURE_TENANT_ID=' . getenv('TEST_TENANT_ID'));
        putenv('AZURE_CLIENT_ID=' . getenv('TEST_CLIENT_ID'));
        putenv('AZURE_CLIENT_SECRET=' . getenv('TEST_CLIENT_SECRET'));
        $this->clearSecrets();
    }

    private function clearSecrets(): void
    {
        $client = new Client(
            new GuzzleClientFactory(new NullLogger()),
            new AuthenticatorFactory(),
            (string) getenv('TEST_KEY_VAULT_URL'),
        );
        foreach ($client->getAllSecrets() as $secret) {
            $client->deleteSecret($secret->getName());
        }
    }

    public function testEncryptDecrypt(): void
    {
        $payload = ')_+\\(*&^%$#@!)/"\'junk';
        $logger = new TestLogger();
        $client = new Client(
            new GuzzleClientFactory($logger),
            new AuthenticatorFactory(),
            (string) getenv('TEST_KEY_VAULT_URL'),
        );
        $result = $client->encrypt(
            new EncryptRequest(EncryptDecryptRequest::RSA_OAEP_256, $payload),
            (string) getenv('TEST_KEY_NAME'),
            (string) getenv('TEST_KEY_VERSION'),
        );
        self::assertNotEquals($payload, $result->getValue(false));
        self::assertNotEquals($payload, $result->getValue(true));
        self::assertGreaterThan(300, strlen($result->getValue(false)));
        self::assertEquals(
            getenv('TEST_KEY_VAULT_URL') . '/keys/' . getenv('TEST_KEY_NAME') .
            '/' . getenv('TEST_KEY_VERSION'),
            $result->getKid(),
        );
        $result = $client->decrypt(
            new DecryptRequest(EncryptDecryptRequest::RSA_OAEP_256, $result->getValue(false)),
            (string) getenv('TEST_KEY_NAME'),
            (string) getenv('TEST_KEY_VERSION'),
        );
        self::assertEquals($payload, $result->getValue(true));
        self::assertEquals(
            getenv('TEST_KEY_VAULT_URL') . '/keys/' . getenv('TEST_KEY_NAME') .
            '/' . getenv('TEST_KEY_VERSION'),
            $result->getKid(),
        );
    }

    public function testSetGetSecret(): void
    {
        $payload = ')_+\\(*&^%$#@!)/"\'junk';
        $logger = new TestLogger();
        $client = new Client(
            new GuzzleClientFactory($logger),
            new AuthenticatorFactory(),
            (string) getenv('TEST_KEY_VAULT_URL'),
        );
        $result = $client->setSecret(
            new SetSecretRequest($payload, new SecretAttributes(), null, ['a' => 'b', 'c' => 'd']),
            uniqid('my-secret'),
        );
        self::assertEquals($payload, $result->getValue());

        $getResult = $client->getSecret($result->getName(), $result->getVersion());
        self::assertEquals($payload, $getResult->getValue());
        self::assertEquals(['a' => 'b', 'c' => 'd'], $getResult->getTags());
    }

    public function testGetSecretDefaultVersion(): void
    {
        $payload = ')_+\\(*&^%$#@!)/"\'junk';
        $logger = new TestLogger();
        $client = new Client(
            new GuzzleClientFactory($logger),
            new AuthenticatorFactory(),
            (string) getenv('TEST_KEY_VAULT_URL'),
        );
        $secretName = uniqid('my-secret');
        $client->setSecret(
            new SetSecretRequest($payload, new SecretAttributes(), null, ['a' => 'b', 'c' => 'd']),
            $secretName,
        );
        $payload = 'test';
        $result = $client->setSecret(
            new SetSecretRequest($payload, new SecretAttributes(), null, ['a' => 'b', 'c' => 'd']),
            $secretName,
        );
        self::assertEquals($payload, $result->getValue());

        $getResult = $client->getSecret($result->getName());
        self::assertEquals('test', $getResult->getValue());
        self::assertEquals(['a' => 'b', 'c' => 'd'], $getResult->getTags());
    }

    public function testGetSecrets(): void
    {
        $client = new Client(
            new GuzzleClientFactory(new NullLogger()),
            new AuthenticatorFactory(),
            (string) getenv('TEST_KEY_VAULT_URL'),
        );
        $client->setSecret(new SetSecretRequest('test1', new SecretAttributes()), uniqid('test-secret1'));
        $client->setSecret(new SetSecretRequest('test2', new SecretAttributes()), uniqid('test-secret2'));
        $client->setSecret(new SetSecretRequest('test3', new SecretAttributes()), uniqid('test-secret3'));
        $secrets = $client->getAllSecrets(2);
        self::assertCount(3, $secrets);
        $names = [];
        foreach ($secrets as $secret) {
            $names[] = substr($secret->getName(), 0, 12);
        }
        self::assertEquals(['test-secret1', 'test-secret2', 'test-secret3'], $names);
    }
}
