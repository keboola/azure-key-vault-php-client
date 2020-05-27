<?php

namespace Keboola\AzureKeyVaultClient;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorInterface;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\Requests\DecryptRequest;
use Keboola\AzureKeyVaultClient\Requests\EncryptRequest;
use Keboola\AzureKeyVaultClient\Requests\SetSecretRequest;
use Keboola\AzureKeyVaultClient\Responses\KeyOperationResult;
use Keboola\AzureKeyVaultClient\Responses\SecretBundle;
use Psr\Http\Message\RequestInterface;
use Psr\Log\LoggerInterface;

class Client
{
    const API_VERSION = '7.0';

    /** @var GuzzleClient */
    private $guzzle;

    /** @var LoggerInterface */
    private $logger;

    /** @var AuthenticatorInterface */
    private $authenticator;

    /** @var string */
    private $token;

    public function __construct(
        GuzzleClientFactory $clientFactory,
        AuthenticatorFactory $authenticatorFactory,
        $vaultBaseUrl
    ) {
        $handlerStack = HandlerStack::create();
        // Set handler to set authorization
        $handlerStack->push(Middleware::mapRequest(
            function (RequestInterface $request) {
                return $request
                    ->withHeader('Authorization', 'Bearer ' . $this->token);
            }
        ));
        $this->logger = $clientFactory->getLogger();
        $this->guzzle = $clientFactory->getClient($vaultBaseUrl, ['handler' => $handlerStack]);
        $this->authenticator = $authenticatorFactory->getAuthenticator($clientFactory);
    }

    private function sendRequest(Request $request)
    {
        try {
            if (!$this->token) {
                $this->token = $this->authenticator->getAuthenticationToken();
                $this->logger->info('Successfully authenticated.');
            }
            $response = $this->guzzle->send($request);
            return \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
        } catch (GuzzleException $e) {
            $this->handleRequestException($e);
            throw new ClientException($e->getMessage(), $e->getCode(), $e);
        }
    }

    private function handleRequestException(GuzzleException $e)
    {
        if ($e->getResponse() && is_a($e->getResponse(), Response::class)) {
            /** @var Response $response */
            $response = $e->getResponse();
            try {
                $data = \GuzzleHttp\json_decode($response->getBody()->getContents(), true);
            } catch (GuzzleException $e2) {
                // throw the original one, we don't care about e2
                throw new ClientException(trim($e->getMessage()), $response->getStatusCode(), $e);
            }
            if (!empty($data['error']) && !empty($data['error']['message']) && !empty($data['error']['code'])) {
                throw new ClientException(
                    trim($data['error']['code'] . ': ' . $data['error']['message']),
                    $response->getStatusCode(),
                    $e
                );
            } elseif (!empty($data['error']) && is_scalar($data['error'])) {
                throw new ClientException(
                    trim('Request failed with error: ' . $data['error']),
                    $response->getStatusCode(),
                    $e
                );
            }
        }
    }

    /**
     * @param EncryptRequest $encryptRequest
     * @param $keyName
     * @param $keyVersion
     * @return KeyOperationResult
     */
    public function encrypt(EncryptRequest $encryptRequest, $keyName, $keyVersion)
    {
        $request = new Request(
            'POST',
            sprintf('keys/%s/%s/encrypt?api-version=%s', $keyName, $keyVersion, self::API_VERSION),
            [],
            \GuzzleHttp\json_encode($encryptRequest->getArray())
        );
        return new KeyOperationResult($this->sendRequest($request));
    }

    /**
     * @param DecryptRequest $encryptRequest
     * @param $keyName
     * @param $keyVersion
     * @return KeyOperationResult
     */
    public function decrypt(DecryptRequest $encryptRequest, $keyName, $keyVersion)
    {
        $request = new Request(
            'POST',
            sprintf('keys/%s/%s/decrypt?api-version=%s', $keyName, $keyVersion, self::API_VERSION),
            [],
            \GuzzleHttp\json_encode($encryptRequest->getArray())
        );
        return new KeyOperationResult($this->sendRequest($request));
    }

    /**
     * @param SetSecretRequest $setSecretRequest
     * @param string $secretName
     * @return SecretBundle
     */
    public function setSecret(SetSecretRequest $setSecretRequest, $secretName)
    {
        $request = new Request(
            'PUT',
            sprintf('secrets/%s?api-version=%s', $secretName, self::API_VERSION),
            [],
            \GuzzleHttp\json_encode($setSecretRequest->getArray())
        );
        return new SecretBundle($this->sendRequest($request));
    }

    /**
     * @param string $secretName
     * @param string $secretVersion
     * @return SecretBundle
     */
    public function getSecret($secretName, $secretVersion)
    {
        $request = new Request(
            'GET',
            sprintf('secrets/%s/%s?api-version=%s', $secretName, $secretVersion, self::API_VERSION)
        );
        return new SecretBundle($this->sendRequest($request));
    }
}
