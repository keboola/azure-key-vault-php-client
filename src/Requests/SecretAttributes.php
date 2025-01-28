<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Requests;

use Keboola\AzureKeyVaultClient\Exception\ClientException;

class SecretAttributes
{
    public const RECOVERY_LEVEL_PURGEABLE = 'Purgeable';
    public const RECOVERY_LEVEL_RECOVERABLE = 'Recoverable';
    public const RECOVERY_LEVEL_RECOVERABLE_PROTECTED_SUBSCRIPTION = 'Recoverable+ProtectedSubscription';
    public const RECOVERY_LEVEL_RECOVERABLE_PURGEABLE = 'Recoverable+Purgeable';

    private ?int $created;
    private ?bool $enabled;
    private ?int $exp;
    private ?int $nbf;
    private ?string $recoveryLevel;
    private ?int $updated;

    public function __construct(
        ?int $created = null,
        ?bool $enabled = null,
        ?int $exp = null,
        ?int $nbf = null,
        ?string $recoveryLevel = null,
        ?int $updated = null
    ) {
        if (!is_null($recoveryLevel) && !in_array(
            $recoveryLevel,
            [
                self::RECOVERY_LEVEL_PURGEABLE,
                self::RECOVERY_LEVEL_RECOVERABLE,
                self::RECOVERY_LEVEL_RECOVERABLE_PROTECTED_SUBSCRIPTION,
                self::RECOVERY_LEVEL_RECOVERABLE_PURGEABLE,
            ],
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

    public static function fromArray(array $attributes): SecretAttributes
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
            $attributes['updated'],
        );
    }

    public function getArray(): array
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
