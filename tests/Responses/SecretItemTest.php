<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Responses\SecretItem;
use PHPUnit\Framework\TestCase;

class SecretItemTest extends TestCase
{
    public function testSecretItemAccessors(): void
    {
        $secretItem = new SecretItem([
            'attributes' => [
                'created' => 1590586213,
                'enabled' => true,
                'exp' => 1590586214,
                'nbf' => 1590586215,
                'recoveryLevel' => 'Purgeable',
                'updated' => 1590586213,
            ],
            'contentType' => 'plain',
            'id' => 'https://test.vault.azure.net/secrets/foo',
            'managed' => false,
            'tags' => [
                'a' => 'b',
                'c' => 'd',
            ],
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
            $secretItem->getAttributes()->getArray()
        );
        self::assertEquals('plain', $secretItem->getContentType());
        self::assertEquals('https://test.vault.azure.net/secrets/foo', $secretItem->getId());
        self::assertEquals(false, $secretItem->isManaged());
        self::assertEquals(
            [
                'a' => 'b',
                'c' => 'd',
            ],
            $secretItem->getTags()
        );
        self::assertEquals('foo', $secretItem->getName());
    }

    public function testSecretItemInvalid(): void
    {
        self::expectException(InvalidResponseException::class);
        self::expectExceptionMessage('SecretItem is invalid: []');
        new SecretItem([]);
    }

    public function testSecretItemInvalidId(): void
    {
        $secretItem = new SecretItem([
            'attributes' => [],
            'contentType' => 'plain',
            'id' => 'malformed',
            'kid' => 'https://test.vault.azure.net/secrets',
            'managed' => false,
            'value' => 'so-secret',
        ]);
        self::expectException(InvalidResponseException::class);
        self::expectExceptionMessage('Invalid secret ID format "malformed".');
        $secretItem->getName();
    }
}
