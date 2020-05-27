<?php

namespace Keboola\AzureKeyVaultClient\Tests\Requests;

use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Requests\DecryptRequest;
use Keboola\AzureKeyVaultClient\Requests\EncryptRequest;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class EncryptDecryptRequestTest extends TestCase
{
    public function testValidEncryptRequest()
    {
        $request = new EncryptRequest('RSA-OAEP', 'foo');
        self::assertEquals(
            [
                'alg' => 'RSA-OAEP',
                'value' => 'Zm9v',
            ],
            $request->getArray()
        );
    }

    public function testInvalidEncryptAlgorithm()
    {
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Invalid algorithm "bar"');
        new EncryptRequest('bar', 'foo');
    }

    public function testValidDecryptRequest()
    {
        $request = new DecryptRequest('RSA-OAEP', 'foo');
        self::assertEquals(
            [
                'alg' => 'RSA-OAEP',
                'value' => 'foo',
            ],
            $request->getArray()
        );
    }

    public function testInvalidDecryptAlgorithm()
    {
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Invalid algorithm "bar"');
        new DecryptRequest('bar', 'foo');
    }
}
