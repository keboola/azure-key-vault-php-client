<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Requests;

use Keboola\AzureKeyVaultClient\Exception\ClientException;

abstract class EncryptDecryptRequest
{
    public const RSA_OAEP = 'RSA-OAEP';
    public const RSA_OAEP_256 = 'RSA-OAEP-256';
    public const RSA_1_5 = 'RSA1_5';

    protected string $alg;
    protected string $value;

    public function __construct(string $alg, string $value)
    {
        if (!in_array($alg, [self::RSA_OAEP, self::RSA_OAEP_256, self::RSA_1_5])) {
            throw new ClientException(sprintf('Invalid algorithm "%s"', $alg));
        }
        $this->alg = $alg;
        $this->value = $value;
    }

    abstract public function getArray(): array;
}
