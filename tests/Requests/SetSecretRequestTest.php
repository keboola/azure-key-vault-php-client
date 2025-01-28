<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests\Requests;

use Keboola\AzureKeyVaultClient\Requests\SecretAttributes;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use PHPUnit\Framework\TestCase;

class SetSecretRequestTest extends TestCase
{
    public function testSetSecretRequestFull(): void
    {
        $request = new SetSecretRequest('so-secret', new SecretAttributes(123), 'plain', ['a' => 'b']);
        self:self::assertEquals(
            [
                'value' => 'so-secret',
                'attributes' => [
                    'created' => 123,
                ],
                'contentType' => 'plain',
                'tags' => ['a' => 'b'],
            ],
            $request->getArray(),
        );
    }

    public function testSetSecretRequestMinimal(): void
    {
        $request = new SetSecretRequest('so-secret', new SecretAttributes());
        self:self::assertEquals(
            [
                'value' => 'so-secret',
            ],
            $request->getArray(),
        );
    }
}
