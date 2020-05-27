<?php

namespace Keboola\AzureKeyVaultClient\Requests;

use Keboola\AzureKeyVaultClient\Exception\ClientException;

class SecretAttributes
{
    const RECOVERY_LEVEL_PURGEABLE = 'Purgeable';
    const RECOVERY_LEVEL_RECOVERABLE = 'Recoverable';
    const RECOVERY_LEVEL_RECOVERABLE_PROTECTED_SUBSCRIPTION = 'Recoverable+ProtectedSubscription';
    const RECOVERY_LEVEL_RECOVERABLE_PURGEABLE = 'Recoverable+Purgeable';

    /** @var int */
    private $created;

    /** @var bool */
    private $enabled;

    /** @var int */
    private $exp;

    /** @var int */
    private $nbf;

    /** @var string */
    private $recoveryLevel;

    /** @var int */
    private $updated;

    /**
     * @param string $created
     * @param string $enabled
     * @param string $exp
     * @param string $nbf
     * @param string $recoveryLevel
     * @param string $updated
     */
    public function __construct($created = null, $enabled = null, $exp = null, $nbf = null, $recoveryLevel = null, $updated = null)
    {
        if (!is_null($recoveryLevel) && !in_array(
            $recoveryLevel, [
                self::RECOVERY_LEVEL_PURGEABLE,
                self::RECOVERY_LEVEL_RECOVERABLE,
                self::RECOVERY_LEVEL_RECOVERABLE_PROTECTED_SUBSCRIPTION,
                self::RECOVERY_LEVEL_RECOVERABLE_PURGEABLE,
            ]
        )) {
            throw new ClientException(sprintf('Invalid recovery level "%s"', $recoveryLevel));
        }
        $this->created = $created;
        $this->enabled = $enabled;
        $this->exp = $exp;
        $this->nbf = $nbf;
        $this->recoveryLevel = $recoveryLevel;
        $this->updated = $updated;
    }

    /**
     * @param array $attributes
     * @return SecretAttributes
     */
    public static function fromArray(array $attributes)
    {
        foreach (['created', 'enabled', 'exp', 'nbf', 'recoveryLevel', 'updated'] as $field) {
            if (!isset($attributes[$field])) {
                $attributes[$field] = null;
            }
        }
        return new SecretAttributes(
            $attributes['created'],
            $attributes['enabled'],
            $attributes['exp'],
            $attributes['nbf'],
            $attributes['recoveryLevel'],
            $attributes['updated']
        );
    }

    /**
     * @return array
     */
    public function getArray()
    {
        $result = [];
        if (!is_null($this->created)) {
            $result['created'] = (int) $this->created;
        }
        if (!is_null($this->enabled)) {
            $result['enabled'] = (bool) $this->enabled;
        }
        if (!is_null($this->exp)) {
            $result['exp'] = (int) $this->exp;
        }
        if (!is_null($this->nbf)) {
            $result['nbf'] = (int) $this->nbf;
        }
        if (!is_null($this->recoveryLevel)) {
            $result['recoveryLevel'] = (string) $this->recoveryLevel;
        }
        if (!is_null($this->updated)) {
            $result['updated'] = (int) $this->updated;
        }
        return $result;
    }
}
