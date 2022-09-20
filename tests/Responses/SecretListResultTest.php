<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Responses\SecretListResult;
use PHPUnit\Framework\TestCase;

class SecretListResultTest extends TestCase
{
    public function testSecretListResultFull(): void
    {
        $secretItemList = new SecretListResult([
            'value' => [
                [
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
                ],
                [
                    'attributes' => [
                        'created' => 290586213,
                        'enabled' => false,
                        'exp' => 290586214,
                        'nbf' => 290586215,
                        'recoveryLevel' => 'Recoverable',
                        'updated' => 290586213,
                    ],
                    'contentType' => 'clumsy',
                    'id' => 'https://test.vault.azure.net/secrets/bar',
                    'managed' => true,
                    'tags' => [
                        'd' => 'c',
                        'b' => 'a',
                    ],
                ],
            ],
            'nextLink' => 'https://example.com/next',
        ]);
        $secretItem = $secretItemList->getValue()[0];
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
        $secretItem = $secretItemList->getValue()[1];
        self::assertEquals(
            [
                'created' => 290586213,
                'enabled' => false,
                'exp' => 290586214,
                'nbf' => 290586215,
                'recoveryLevel' => 'Recoverable',
                'updated' => 290586213,
            ],
            $secretItem->getAttributes()->getArray()
        );
        self::assertEquals('clumsy', $secretItem->getContentType());
        self::assertEquals('https://test.vault.azure.net/secrets/bar', $secretItem->getId());
        self::assertEquals(true, $secretItem->isManaged());
        self::assertEquals(
            [
                'd' => 'c',
                'b' => 'a',
            ],
            $secretItem->getTags()
        );
        self::assertEquals('bar', $secretItem->getName());
        self::assertEquals('https://example.com/next', $secretItemList->getNextLink());
    }

    public function testSecretListInvalid(): void
    {
        self::expectException(InvalidResponseException::class);
        self::expectExceptionMessage('SecretListResult is invalid: []');
        new SecretListResult([]);
    }

    public function testSecretListMinimal(): void
    {
        $secretListResult = new SecretListResult(['value' => []]);
        self::assertEquals([], $secretListResult->getValue());
        self::assertNull($secretListResult->getNextLink());
    }
}
