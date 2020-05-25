<?php

namespace Keboola\AzureKeyVaultClient\Requests;

use Keboola\AzureKeyVaultClient\Exception\ClientException;

class EncryptDecryptRequest
{
    const RSA_OAEP = 'RSA-OAEP';
    const RSA_OAEP_256 = 'RSA-OAEP-256';
    const RSA_1_5 = 'RSA1_5';

    /** @var string */
    private $alg;
    /** @var string */
    private $value;

    /**
     * @param string $alg
     * @param string $value
     */
    public function __construct($alg, $value)
    {
        if (!in_array($alg, [self::RSA_OAEP, self::RSA_OAEP_256, self::RSA_1_5])) {
            throw new ClientException(sprintf('Invalid algorithm "%s"', $alg));
        }
        $this->alg = (string) $alg;
        $this->value = (string) $value;
    }

    public function getArray()
    {
        return [
            'alg' => $this->alg,
            'value' => $this->value,
        ];
    }
}
