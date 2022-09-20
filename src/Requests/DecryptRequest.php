<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Requests;

class DecryptRequest extends EncryptDecryptRequest
{
    public function getArray(): array
    {
        return [
            'alg' => $this->alg,
            'value' => $this->value,
        ];
    }
}
