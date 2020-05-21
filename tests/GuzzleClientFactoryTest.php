<?php

namespace Keboola\AzureKeyVaultClient\Tests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Psr\Log\Test\TestLogger;

class GuzzleClientFactoryTest extends TestCase
{
    public function testGetClient()
    {
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('http://example.com');
        self::assertInstanceOf(Client::class, $client);
        self::assertInstanceOf(NullLogger::class, $factory->getLogger());
    }

    /**
     * @dataProvider invalidOptionsProvider
     * @param array $options
     * @param string $expectedMessage
     */
    public function testInvalidOptions(array $options, $expectedMessage)
    {
        $factory = new GuzzleClientFactory(new NullLogger());
        self::expectException(ClientException::class);
        self::expectExceptionMessage($expectedMessage);
        $factory->getClient('http://example.com', $options);
    }

    /**
     * @return array
     */
    public function invalidOptionsProvider()
    {
        return [
            'invalid-options' => [
                [
                    'non-existent' => 'foo',
                ],
                'Invalid options when creating client: non-existent. Valid options are: backoffMaxTries, userAgent, handler, logger.',
            ],
            'invalid-backoff' => [
                [
                    'backoffMaxTries' => 'foo',
                ],
                'Invalid options when creating client: Value "foo" is invalid: This value should be a valid number.',
            ],
        ];
    }

    public function testInvalidUrl()
    {
        $factory = new GuzzleClientFactory(new NullLogger());
        self::expectException(ClientException::class);
        self::expectExceptionMessage('boo');
        $factory->getClient('boo', []);
    }

    public function testLogger()
    {
        $logger = new TestLogger();
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['logger' => $logger, 'userAgent' => 'test-client']);
        $client->get('');
        self::assertTrue($logger->hasInfoThatContains('test-client - ['));
        self::assertTrue($logger->hasInfoThatContains('"GET  /1.1" 200'));
    }

    public function testDefaultHeader()
    {
        $mock = new MockHandler([
            new Response(
                200,
                [],
                'boo'
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);

        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['handler' => $stack, 'userAgent' => 'test-client']);
        $client->get('');

        self::assertCount(1, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        self::assertEquals('GET', $request->getMethod());
        self::assertEquals('test-client', $request->getHeader('User-Agent')[0]);
        // default header
        self::assertEquals('application/json', $request->getHeader('Content-type')[0]);

    }

    public function testRetryDeciderNoRetry()
    {
        $mock = new MockHandler([
            new Response(
                403,
                [],
                'boo'
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);

        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['handler' => $stack, 'userAgent' => 'test-client']);
        try {
            $client->get('');
            self::fail('Must throw exception');
        } catch (\GuzzleHttp\Exception\ClientException $e) {
            self::assertContains('Client error: `GET https://example.com` resulted in a `403 Forbidden` response', $e->getMessage());
        }

        self::assertCount(1, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
    }

    public function testRetryDeciderRetryFail()
    {
        $mock = new MockHandler([
            new Response(
                501,
                [],
                'boo'
            ),
            new Response(
                501,
                [],
                'boo'
            ),
            new Response(
                501,
                [],
                'boo'
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);

        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['handler' => $stack, 'userAgent' => 'test-client', 'backoffMaxTries' => 2]);
        try {
            $client->get('');
            self::fail('Must throw exception');
        } catch (ServerException $e) {
            self::assertContains('Server error: `GET https://example.com` resulted in a `501 Not Implemented`', $e->getMessage());
        }

        self::assertCount(3, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        $request = $requestHistory[1]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        $request = $requestHistory[2]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
    }

    public function testRetryDeciderRetrySuccess()
    {
        $mock = new MockHandler([
            new Response(
                501,
                [],
                'boo'
            ),
            new Response(
                501,
                [],
                'boo'
            ),
            new Response(
                200,
                [],
                'boo'
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $logger = new TestLogger();
        $factory = new GuzzleClientFactory($logger);
        $client = $factory->getClient('https://example.com', ['handler' => $stack, 'userAgent' => 'test-client', 'backoffMaxTries' => 2]);
        $client->get('');

        self::assertCount(3, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        $request = $requestHistory[1]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        $request = $requestHistory[2]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        self::assertTrue($logger->hasWarningThatContains('Request failed (Server error: `GET https://example.com` resulted in a `501 Not Implemented`'));
        self::assertTrue($logger->hasWarningThatContains('retrying (1 of 2)'));
    }

    public function testRetryDeciderThrottlingRetrySuccess()
    {
        $mock = new MockHandler([
            new Response(
                429,
                [],
                'boo'
            ),
            new Response(
                429,
                [],
                'boo'
            ),
            new Response(
                200,
                [],
                'boo'
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $logger = new TestLogger();
        $factory = new GuzzleClientFactory($logger);
        $client = $factory->getClient('https://example.com', ['handler' => $stack, 'userAgent' => 'test-client', 'backoffMaxTries' => 2]);
        $client->get('');

        self::assertCount(3, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        $request = $requestHistory[1]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        $request = $requestHistory[2]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        self::assertTrue($logger->hasWarningThatContains('Request failed (Client error: `GET https://example.com` resulted in a `429 Too Many Requests`'));
        self::assertTrue($logger->hasWarningThatContains('retrying (1 of 2)'));
    }
}
