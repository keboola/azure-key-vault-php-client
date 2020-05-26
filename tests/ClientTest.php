<?php

namespace Keboola\AzureKeyVaultClient\Tests;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Requests\EncryptRequest;
use Psr\Log\NullLogger;
use Psr\Log\Test\TestLogger;

class ClientTest extends BaseTest
{
    public function testEncrypt()
    {
        $mock = new MockHandler([
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode($this->getSampleArmMetadata())
            ),
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                '{
                    "token_type": "Bearer",
                    "expires_in": "3599",
                    "ext_expires_in": "3599",
                    "expires_on": "1589810452",
                    "not_before": "1589806552",
                    "resource": "https://vault.azure.net",
                    "access_token": "ey....ey"
                }'
            ),
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                '{
                    "kid": "https://my-test.vault.azure.net/keys/test-key/test-version",
                    "value": "someEncryptedValue"
                }'
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->setConstructorArgs([new NullLogger()])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $client = new Client($factory, new AuthenticatorFactory(), 'https://my-test.vault.azure.net');
        $result = $client->encrypt(
            new EncryptRequest('RSA1_5', 'test'),
            'test-key',
            'test-version'
        );
        self::assertNotEquals('test', $result->getValue(true));
        self::assertNotEquals('test', $result->getValue(false));
        self::assertEquals('https://my-test.vault.azure.net/keys/test-key/test-version', $result->getKid());

        self::assertCount(3, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://management.azure.com/metadata/endpoints?api-version=2020-01-01', $request->getUri()->__toString());
        /** @var Request $request */
        $request = $requestHistory[1]['request'];
        self::assertEquals('https://login.windows.net/tenant123/oauth2/token', $request->getUri()->__toString());
        /** @var Request $request */
        $request = $requestHistory[2]['request'];
        self::assertEquals('https://example.com/keys/test-key/test-version/encrypt?api-version=7.0', $request->getUri()->__toString());
        self::assertEquals('POST', $request->getMethod());
        self::assertEquals('Azure PHP Client', $request->getHeader('User-Agent')[0]);
        self::assertEquals('application/json', $request->getHeader('Content-type')[0]);
        self::assertEquals('{"alg":"RSA1_5","value":"dGVzdA"}', $request->getBody()->getContents());
    }

    /**
     * @dataProvider errorProvider
     * @param string $body
     * @param string $expectedError
     */
    public function testEncryptClientError($body, $expectedError)
    {
        $mock = new MockHandler(array_merge(
                $this->getMockAuthResponses(),
                [new Response(
                    400,
                    ['Content-Type' => 'application/json'],
                    $body
                )]
            )
        );

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $logger = new TestLogger();
        $factory = new GuzzleClientFactory($logger);
        $client = $factory->getClient('https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->setConstructorArgs([$logger])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $client = new Client($factory, new AuthenticatorFactory(), 'https://my-test.vault.azure.net');
        try {
            $client->encrypt(
                new EncryptRequest('RSA1_5', 'test'),
                'test-key',
                'test-version'
            );
            self::fail('Must throw exception');
        } catch (ClientException $e) {
            self::assertEquals($expectedError, $e->getMessage());
            self::assertEquals(400, $e->getCode());
        }
        self::assertFalse($logger->hasWarningThatContains('Request failed'));
        self::assertFalse($logger->hasWarningThatContains('retrying'));
        self::assertCount(3, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://management.azure.com/metadata/endpoints?api-version=2020-01-01', $request->getUri()->__toString());
        $request = $requestHistory[1]['request'];
        self::assertEquals('https://login.windows.net/tenant123/oauth2/token', $request->getUri()->__toString());
        $request = $requestHistory[2]['request'];
        self::assertEquals('https://example.com/keys/test-key/test-version/encrypt?api-version=7.0', $request->getUri()->__toString());
    }

    public function errorProvider()
    {
        return [
            'graceful-error' => [
                '{
                    "error": {
                        "code": "BadParameter",
                        "message": "Property  has invalid value\r\n"
                    }
                }',
                'BadParameter: Property  has invalid value'
            ],
            'less-graceful-error' => [
                '{
                    "error": "Cooties!"
                }',
                'Request failed with error: Cooties!'
            ],
            'not-graceful' => [
                '{"broken',
                "Client error: `POST https://example.com/keys/test-key/test-version/encrypt?api-version=7.0` resulted in a `400 Bad Request` response:\n{\"broken"
            ],
            'not-graceful-at-all' => [
                '<HTLMTL Transitional>Cooties!',
                "Client error: `POST https://example.com/keys/test-key/test-version/encrypt?api-version=7.0` resulted in a `400 Bad Request` response:\n<HTLMTL Transitional>Cooties!"
            ],
        ];
    }

    public function testEncryptServerError()
    {
        $mock = new MockHandler(
            array_merge(
                $this->getMockAuthResponses(),
                [new Response(
                    500,
                    ['Content-Type' => 'application/json'],
                    '{
                        "error": {
                            "code": "Boo",
                            "message": "Cooties!"
                        }
                    }'
                )],
                array_fill(0, 2, new Response(
                    500,
                    ['Content-Type' => 'application/json'],
                    '{
                        "error": {
                            "code": "Boo",
                            "message": "Cooties!"
                        }
                    }'
                ))
            )
        );

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $logger = new TestLogger();
        $factory = new GuzzleClientFactory($logger);
        $client = $factory->getClient('https://example.com', ['handler' => $stack, 'backoffMaxTries' => 2]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->setConstructorArgs([$logger])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $client = new Client($factory, new AuthenticatorFactory(), 'https://my-test.vault.azure.net');
        try {
            $client->encrypt(
                new EncryptRequest('RSA1_5', 'test'),
                'test-key',
                'test-version'
            );
            self::fail('Must throw exception');
        } catch (ClientException $e) {
            self::assertEquals('Boo: Cooties!', $e->getMessage());
            self::assertEquals(500, $e->getCode());
        }
        self::assertTrue($logger->hasWarningThatContains('Request failed (Server error: `POST https://example.com'));
        self::assertTrue($logger->hasWarningThatContains('retrying (1 of 2)'));
        self::assertCount(5, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://management.azure.com/metadata/endpoints?api-version=2020-01-01', $request->getUri()->__toString());
        $request = $requestHistory[1]['request'];
        self::assertEquals('https://login.windows.net/tenant123/oauth2/token', $request->getUri()->__toString());
        $request = $requestHistory[2]['request'];
        self::assertEquals('https://example.com/keys/test-key/test-version/encrypt?api-version=7.0', $request->getUri()->__toString());
        $request = $requestHistory[3]['request'];
        self::assertEquals('https://example.com/keys/test-key/test-version/encrypt?api-version=7.0', $request->getUri()->__toString());
        $request = $requestHistory[4]['request'];
        self::assertEquals('https://example.com/keys/test-key/test-version/encrypt?api-version=7.0', $request->getUri()->__toString());
    }
}
