<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Requests;

use Keboola\AzureKeyVaultClient\Base64UrlEncoder;

class EncryptRequest extends EncryptDecryptRequest
{
    public function getArray(): array
    {
        return [
            'alg' => $this->alg,
            'value' => Base64UrlEncoder::encode($this->value),
        ];
    }
}
