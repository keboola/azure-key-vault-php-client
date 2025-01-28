<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use JsonException;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorInterface;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\Requests\DecryptRequest;
use Keboola\AzureKeyVaultClient\Requests\EncryptRequest;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use Keboola\AzureKeyVaultClient\Responses\DeletedSecretBundle;
use Keboola\AzureKeyVaultClient\Responses\KeyOperationResult;
use Keboola\AzureKeyVaultClient\Responses\SecretBundle;
use Keboola\AzureKeyVaultClient\Responses\SecretItem;
use Keboola\AzureKeyVaultClient\Responses\SecretListResult;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use Throwable;

class Client
{
    private const API_VERSION = '7.0';
    private const DEFAULT_PAGE_SIZE = 25;

    private GuzzleClient $guzzle;
    private LoggerInterface $logger;
    private AuthenticatorInterface $authenticator;
    private string $token;

    public function __construct(
        GuzzleClientFactory $clientFactory,
        AuthenticatorFactory $authenticatorFactory,
        string $vaultBaseUrl
    ) {
        $handlerStack = HandlerStack::create();
        // Set handler to set authorization
        $handlerStack->push(Middleware::mapRequest(
            function (RequestInterface $request) {
                return $request
                    ->withHeader('Authorization', 'Bearer ' . $this->token);
            },
        ));
        $this->logger = $clientFactory->getLogger();
        $this->guzzle = $clientFactory->getClient($vaultBaseUrl, ['handler' => $handlerStack]);
        $this->authenticator = $authenticatorFactory->getAuthenticator($clientFactory, 'https://vault.azure.net');
    }

    private function sendRequest(Request $request): array
    {
        try {
            if (empty($this->token)) {
                $this->token = $this->authenticator->getAuthenticationToken();
                $this->logger->info('Successfully authenticated.');
            }
            $response = $this->guzzle->send($request);
            return (array) json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException | GuzzleException $e) {
            if (is_a($e, RequestException::class) && $e->getResponse()) {
                $this->handleRequestException($e, $e->getResponse());
            }
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
        }
    }

    private function handleRequestException(RequestException $e, ResponseInterface $response): void
    {
        try {
            $data = (array) json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e2) {
            // throw the original one, we don't care about e2
            throw new ClientException(trim($e->getMessage()), $response->getStatusCode(), $e);
        }
        if (!empty($data['error']) && is_array($data['error']) &&
            !empty($data['error']['message']) && !empty($data['error']['code'])
        ) {
            throw new ClientException(
                trim($data['error']['code'] . ': ' . $data['error']['message']),
                $response->getStatusCode(),
                $e,
            );
        } elseif (!empty($data['error']) && is_scalar($data['error'])) {
            throw new ClientException(
                trim('Request failed with error: ' . $data['error']),
                $response->getStatusCode(),
                $e,
            );
        }
    }

    public function encrypt(EncryptRequest $encryptRequest, string $keyName, string $keyVersion): KeyOperationResult
    {
        $request = new Request(
            'POST',
            sprintf('keys/%s/%s/encrypt?api-version=%s', $keyName, $keyVersion, self::API_VERSION),
            [],
            (string) json_encode($encryptRequest->getArray(), JSON_THROW_ON_ERROR),
        );
        return new KeyOperationResult($this->sendRequest($request));
    }

    public function decrypt(DecryptRequest $encryptRequest, string $keyName, string $keyVersion): KeyOperationResult
    {
        $request = new Request(
            'POST',
            sprintf('keys/%s/%s/decrypt?api-version=%s', $keyName, $keyVersion, self::API_VERSION),
            [],
            (string) json_encode($encryptRequest->getArray(), JSON_THROW_ON_ERROR),
        );
        return new KeyOperationResult($this->sendRequest($request));
    }

    public function setSecret(SetSecretRequest $setSecretRequest, string $secretName): SecretBundle
    {
        $request = new Request(
            'PUT',
            sprintf('secrets/%s?api-version=%s', $secretName, self::API_VERSION),
            [],
            (string) json_encode($setSecretRequest->getArray(), JSON_THROW_ON_ERROR),
        );
        return new SecretBundle($this->sendRequest($request));
    }

    public function getSecret(string $secretName, ?string $secretVersion = null): SecretBundle
    {
        if ($secretVersion === null) {
            $request = new Request(
                'GET',
                sprintf('secrets/%s?api-version=%s', $secretName, self::API_VERSION),
            );
        } else {
            $request = new Request(
                'GET',
                sprintf('secrets/%s/%s?api-version=%s', $secretName, $secretVersion, self::API_VERSION),
            );
        }
        return new SecretBundle($this->sendRequest($request));
    }

    public function getSecrets(int $maxResults = self::DEFAULT_PAGE_SIZE): SecretListResult
    {
        $request = new Request(
            'GET',
            sprintf('secrets/?maxresults=%s&api-version=%s', $maxResults, self::API_VERSION),
        );
        return new SecretListResult($this->sendRequest($request));
    }

    /**
     * @return SecretItem[]
     */
    public function getAllSecrets(int $pageSize = self::DEFAULT_PAGE_SIZE): array
    {
        $listResult = $this->getSecrets($pageSize);
        $items = $listResult->getValue();
        while ($listResult->getNextLink()) {
            $request = new Request(
                'GET',
                $listResult->getNextLink(),
            );
            $listResult = new SecretListResult($this->sendRequest($request));
            $items = array_merge($items, $listResult->getValue());
        }
        return $items;
    }

    public function deleteSecret(string $secretName): DeletedSecretBundle
    {
        $request = new Request(
            'DELETE',
            sprintf('secrets/%s?api-version=%s', $secretName, self::API_VERSION),
        );
        return new DeletedSecretBundle($this->sendRequest($request));
    }
}
