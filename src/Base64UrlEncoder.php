<?php

namespace Keboola\AzureKeyVaultClient;

class Base64UrlEncoder
{
    public static function encode($data) {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function decode($data) {
        return base64_decode(strtr($data, '-_', '+/'), true);
    }
}
