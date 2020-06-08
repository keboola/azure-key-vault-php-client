<?php

namespace Keboola\AzureKeyVaultClient\Tests\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Responses\DeletedSecretBundle;
use PHPUnit\Framework\TestCase;

class DeletedSecretBundleTest extends TestCase
{
    public function testDeletedSecretBundleFull()
    {
        $deletedSecretBundle = new DeletedSecretBundle([
            'attributes' => [
                'created' => 1590586213,
                'enabled' => true,
                'exp' => '1590586214',
                'nbf' => '1590586215',
                'recoveryLevel' => 'Purgeable',
                'updated' => 1590586213,
            ],
            'contentType' => 'plain',
            'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
            'kid' => 'https://test.vault.azure.net/secrets/bar',
            'managed' => false,
            'tags' => [
                'a' => 'b',
                'c' => 'd'
            ],
            'value' => 'so-secret',
            'recoveryId' => 'https://test.azure-int.net/deletedsecrets/foo',
            'deletedDate' => 1493938433,
            'scheduledPurgeDate' => 1501714433,
        ]);
        self::assertEquals([
            'created' => 1590586213,
            'enabled' => true,
            'exp' => 1590586214,
            'nbf' => 1590586215,
            'recoveryLevel' => 'Purgeable',
            'updated' => 1590586213,
        ],
            $deletedSecretBundle->getAttributes()->getArray()
        );
        self::assertEquals('plain', $deletedSecretBundle->getContentType());
        self::assertEquals('https://test.vault.azure.net/secrets/foo/53af0dad94f248', $deletedSecretBundle->getId());
        self::assertEquals('https://test.vault.azure.net/secrets/bar', $deletedSecretBundle->getKid());
        self::assertEquals(false, $deletedSecretBundle->isManaged());
        self::assertEquals(
            [
                'a' => 'b',
                'c' => 'd',
            ],
            $deletedSecretBundle->getTags()
        );
        self::assertEquals('so-secret', $deletedSecretBundle->getValue());
        self::assertEquals('foo', $deletedSecretBundle->getName());
        self::assertEquals('53af0dad94f248', $deletedSecretBundle->getVersion());
        self::assertEquals(1493938433, $deletedSecretBundle->getDeletedDate());
        self::assertEquals('https://test.azure-int.net/deletedsecrets/foo', $deletedSecretBundle->getRecoveryId());
        self::assertEquals(1501714433, $deletedSecretBundle->getScheduledPurgeDate());
    }

    public function testDeletedSecretBundleInvalid()
    {
        self::expectException(InvalidResponseException::class);
        self::expectExceptionMessage('DeletedSecretBundle is invalid: []');
        new DeletedSecretBundle([]);
    }

    public function testDeletedSecretBundleMinimal()
    {
        $deletedSecretBundle = new DeletedSecretBundle([
            'attributes' => [
                'created' => 1590586213,
                'enabled' => true,
                'exp' => '1590586214',
                'nbf' => '1590586215',
                'recoveryLevel' => 'Purgeable',
                'updated' => 1590586213,
            ],
            'id' => 'https://test.vault.azure.net/secrets/foo/53af0dad94f248',
        ]);
        self::assertEquals([
            'created' => 1590586213,
            'enabled' => true,
            'exp' => 1590586214,
            'nbf' => 1590586215,
            'recoveryLevel' => 'Purgeable',
            'updated' => 1590586213,
        ],
            $deletedSecretBundle->getAttributes()->getArray()
        );
        self::assertEquals('https://test.vault.azure.net/secrets/foo/53af0dad94f248', $deletedSecretBundle->getId());
        self::assertEquals('foo', $deletedSecretBundle->getName());
        self::assertEquals('53af0dad94f248', $deletedSecretBundle->getVersion());
    }
}
