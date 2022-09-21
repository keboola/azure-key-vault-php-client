<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests\Responses;

use Generator;
use Keboola\AzureKeyVaultClient\Base64UrlEncoder;
use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Responses\KeyOperationResult;
use PHPUnit\Framework\TestCase;

class KeyOperationResultTest extends TestCase
{
    public function testValidResponseRaw(): void
    {
        $data = [
            'kid' => 'key id',
            'value' => 'some value',
        ];
        $metadata = new KeyOperationResult($data);
        self::assertEquals('key id', $metadata->getKid());
        self::assertEquals('some value', $metadata->getValue(false));
    }

    public function testValidResponseDecode(): void
    {
        $data = [
            'kid' => 'key id',
            'value' => Base64UrlEncoder::encode('some value'),
        ];
        $metadata = new KeyOperationResult($data);
        self::assertEquals('key id', $metadata->getKid());
        self::assertEquals('some value', $metadata->getValue(true));
    }

    /**
     * @dataProvider invalidResponseProvider
     */
    public function testInvalidValidResponse(array $data, string $expectedMessage): void
    {
        self::expectException(InvalidResponseException::class);
        self::expectExceptionMessage($expectedMessage);
        new KeyOperationResult($data);
    }

    public function invalidResponseProvider(): Generator
    {
        yield 'missing key' => [
            [
                'value' => 'some value',
            ],
            'KeyOperationResult is invalid: {"value":"some value"}',
        ];
        yield 'missing value' => [
            [
                'kid' => 'key id',
            ],
            'KeyOperationResult is invalid: {"kid":"key id"}',
        ];
    }
}
