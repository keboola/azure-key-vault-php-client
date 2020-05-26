<?php

namespace Keboola\AzureKeyVaultClient\Tests;

use Keboola\AzureKeyVaultClient\Base64UrlEncoder;
use PHPUnit\Framework\TestCase;

class Base64UrlEncoderTest extends TestCase
{
    /**
     * @dataProvider paddingStringProvider
     * @param string $string
     * @param string $encoded
     */
    public function testEncoder($string, $encoded)
    {
        $result = Base64UrlEncoder::encode($string);
        self::assertEquals($encoded, $result);
        self::assertEquals($string, Base64UrlEncoder::decode($result));
    }

    public function paddingStringProvider()
    {
        return [
            [
                ')_+\\(*&^%$#@!)=/"\'junk',
                'KV8rXCgqJl4lJCNAISk9LyInanVuaw',
            ],
            [
                '+',
                'Kw',
            ],
            [
                '++',
                'Kys',
            ],
            [
                '+++',
                'Kysr',
            ],
            [
                '++++',
                'KysrKw',
            ],
            [
                '+++++',
                'KysrKys',
            ],
        ];
    }
}
