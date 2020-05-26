<?php

namespace Keboola\AzureKeyVaultClient\Requests;

use Keboola\AzureKeyVaultClient\Base64UrlEncoder;
use Keboola\AzureKeyVaultClient\Exception\ClientException;

class EncryptRequest extends EncryptDecryptRequest
{
    public function getArray()
    {
        return [
            'alg' => $this->alg,
            'value' => Base64UrlEncoder::encode($this->value),
        ];
    }
}
