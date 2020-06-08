<?php

namespace Keboola\AzureKeyVaultClient\Tests\Requests;

use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Requests\SecretAttributes;
use PHPUnit\Framework\TestCase;

class SecretAttributesTest extends TestCase
{
    public function testCreateEmpty()
    {
        $attributes = new SecretAttributes();
        self::assertEquals([], $attributes->getArray());
    }

    public function testCreateFull()
    {
        $attributes = new SecretAttributes('1590586213', 'true', 1590586214, 1590586215, 'Purgeable', '1590586216');
        self::assertEquals(
            [
                'created' => 1590586213,
                'enabled' => true,
                'exp' => 1590586214,
                'nbf' => 1590586215,
                'recoveryLevel' => 'Purgeable',
                'updated' => 1590586216,
            ], 
            $attributes->getArray()
        );
    }

    public function testCreateInvalid()
    {
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Invalid recovery level "invalid"');
        new SecretAttributes(null, null, null, null, 'invalid');
    }

    public function testCreateEmptyArray()
    {
        $attributes = SecretAttributes::fromArray([]);
        self::assertEquals([], $attributes->getArray());
    }

    public function testCreateFullArray()
    {
        $attributes = SecretAttributes::fromArray([
            'created' => '1590586213',
            'enabled' => 'true',
            'exp' => '1590586214',
            'nbf' => 1590586215,
            'recoveryLevel' => 'Purgeable',
            'updated' => 1590586216,
        ]);
        self::assertEquals(
            [
                'created' => 1590586213,
                'enabled' => true,
                'exp' => 1590586214,
                'nbf' => 1590586215,
                'recoveryLevel' => 'Purgeable',
                'updated' => 1590586216,
            ],
            $attributes->getArray()
        );
    }
}
