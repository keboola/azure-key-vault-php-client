<?php

namespace Keboola\AzureKeyVaultClient\Requests;

use Keboola\AzureKeyVaultClient\Base64UrlEncoder;

class DecryptRequest extends EncryptDecryptRequest
{
    public function getArray()
    {
        return [
            'alg' => $this->alg,
            'value' => $this->value,
        ];
    }
}
