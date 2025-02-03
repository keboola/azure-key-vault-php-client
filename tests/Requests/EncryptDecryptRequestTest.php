<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests\Requests;

use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\Requests\DecryptRequest;
use Keboola\AzureKeyVaultClient\Requests\EncryptRequest;
use PHPUnit\Framework\TestCase;

class EncryptDecryptRequestTest extends TestCase
{
    public function testValidEncryptRequest(): void
    {
        $request = new EncryptRequest('RSA-OAEP', 'foo');
        self::assertEquals(
            [
                'alg' => 'RSA-OAEP',
                'value' => 'Zm9v',
            ],
            $request->getArray(),
        );
    }

    public function testInvalidEncryptAlgorithm(): void
    {
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Invalid algorithm "bar"');
        new EncryptRequest('bar', 'foo');
    }

    public function testValidDecryptRequest(): void
    {
        $request = new DecryptRequest('RSA-OAEP', 'foo');
        self::assertEquals(
            [
                'alg' => 'RSA-OAEP',
                'value' => 'foo',
            ],
            $request->getArray(),
        );
    }

    public function testInvalidDecryptAlgorithm(): void
    {
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Invalid algorithm "bar"');
        new DecryptRequest('bar', 'foo');
    }
}
