<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Responses\SecretBundle;
use PHPUnit\Framework\TestCase;

class SecretBundleTest extends TestCase
{
    public function testSecretBundleAccessors(): void
    {
        $secretBundle = new SecretBundle([
            'attributes' => [
                'created' => 1590586213,
                'enabled' => true,
                'exp' => 1590586214,
                'nbf' => 1590586215,
                'recoveryLevel' => 'Purgeable',
                'updated' => 1590586213,
            ],
            'contentType' => 'plain',
            'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
            'kid' => 'https://test.vault.azure.net/secrets/bar',
            'managed' => false,
            'tags' => [
                'a' => 'b',
                'c' => 'd',
            ],
            'value' => 'so-secret',
        ]);
        self::assertEquals(
            [
                'created' => 1590586213,
                'enabled' => true,
                'exp' => 1590586214,
                'nbf' => 1590586215,
                'recoveryLevel' => 'Purgeable',
                'updated' => 1590586213,
            ],
            $secretBundle->getAttributes()->getArray(),
        );
        self::assertEquals('plain', $secretBundle->getContentType());
        self::assertEquals('https://test.vault.azure.net/secrets/foo/53af0dad94f248', $secretBundle->getId());
        self::assertEquals('https://test.vault.azure.net/secrets/bar', $secretBundle->getKid());
        self::assertEquals(false, $secretBundle->isManaged());
        self::assertEquals(
            [
                'a' => 'b',
                'c' => 'd',
            ],
            $secretBundle->getTags(),
        );
        self::assertEquals('so-secret', $secretBundle->getValue());
        self::assertEquals('foo', $secretBundle->getName());
        self::assertEquals('53af0dad94f248', $secretBundle->getVersion());
    }

    public function testSecretBundleInvalid(): void
    {
        self::expectException(InvalidResponseException::class);
        self::expectExceptionMessage('SecretBundle is invalid: []');
        new SecretBundle([]);
    }

    public function testSecretBundleInvalidId(): void
    {
        $secretBundle = new SecretBundle([
            'attributes' => [],
            'contentType' => 'plain',
            'id' => 'malformed',
            'kid' => 'https://test.vault.azure.net/secrets/bar',
            'managed' => false,
            'value' => 'so-secret',
        ]);
        self::expectException(InvalidResponseException::class);
        self::expectExceptionMessage('Invalid secret ID format "malformed".');
        $secretBundle->getName();
    }
}
