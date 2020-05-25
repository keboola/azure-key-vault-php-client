<?php

namespace Keboola\AzureKeyVaultClient\Tests\Responses;

use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\Responses\KeyOperationResult;
use PHPUnit\Framework\TestCase;

class KeyOperationResultTest extends TestCase
{
    public function testValidResponse()
    {
        $data = [
            'kid' => 'key id',
            'value' => 'some value',
        ];
        $metadata = new KeyOperationResult($data);
        self::assertEquals('key id', $metadata->getKid());
        self::assertEquals('some value', $metadata->getValue());
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
        new KeyOperationResult($data);
    }

    public function invalidResponseProvider()
    {
        return [
            'missing key' => [
                [
                    'value' => 'some value',
                ],
                'KeyOperationResult is invalid: {"value":"some value"}'
            ],
            'missing value' => [
                [
                    'kid' => 'key id',
                ],
                'KeyOperationResult is invalid: {"kid":"key id"}'
            ],
        ];
    }
}
