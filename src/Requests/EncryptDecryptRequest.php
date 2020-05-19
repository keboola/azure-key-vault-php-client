<?php

namespace Keboola\AzureKeyVaultClient\Requests;

use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Symfony\Component\Validator\Constraints\Choice;
use Symfony\Component\Validator\Validation;

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
        $validator = Validation::createValidator();
        $errors = $validator->validate(
            $alg,
            [new Choice(['min' => 1, 'max' => 1, 'choices' => [self::RSA_OAEP, self::RSA_OAEP_256, self::RSA_1_5]])]
        );
        if ($errors->count() !== 0) {
            throw new ClientException('Invalid encryption request: ' . $errors->get(0)->getMessage());
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
