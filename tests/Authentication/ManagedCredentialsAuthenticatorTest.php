<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests\Authentication;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Keboola\AzureKeyVaultClient\Authentication\ManagedCredentialsAuthenticator;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ManagedCredentialsAuthenticatorTest extends TestCase
{
    public function testGetAuthenticateToken(): void
    {
        $mock = new MockHandler([
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
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['handler' => $stack]);

        $factory = $this->createMock(GuzzleClientFactory::class);
        $factory->method('getClient')->willReturn($client);
        $auth = new ManagedCredentialsAuthenticator($factory, 'https://vault.azure.net');
        $token = $auth->getAuthenticationToken();
        self::assertCount(1, $requestHistory);
        // call second time, value is cached and no new request are made
        $token2 = $auth->getAuthenticationToken();
        self::assertCount(1, $requestHistory);
        self::assertSame($token, $token2);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals(
            // phpcs:ignore Generic.Files.LineLength
            'https://example.com/metadata/identity/oauth2/token?api-version=2019-11-01&format=text&resource=https://vault.azure.net',
            $request->getUri()->__toString()
        );
        self::assertEquals('GET', $request->getMethod());
        self::assertEquals('Azure PHP Client', $request->getHeader('User-Agent')[0]);
        self::assertEquals('true', $request->getHeader('Metadata')[0]);
        self::assertEquals('application/json', $request->getHeader('Content-type')[0]);
    }

    public function testGetAuthenticateInvalid(): void
    {
        $mock = new MockHandler([
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                '{
                    "foo": "bar"
                }'
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['handler' => $stack]);

        $factory = $this->createMock(GuzzleClientFactory::class);
        $factory->method('getClient')->willReturn($client);
        $auth = new ManagedCredentialsAuthenticator($factory, 'https://vault.azure.net');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Access token not provided in response: {"foo":"bar"}');
        $auth->getAuthenticationToken();
    }

    public function testGetAuthenticateMalformed(): void
    {
        $mock = new MockHandler([
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                '{
                    "bar"
                }'
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['handler' => $stack]);

        $factory = $this->createMock(GuzzleClientFactory::class);
        $factory->method('getClient')->willReturn($client);
        $auth = new ManagedCredentialsAuthenticator($factory, 'https://vault.azure.net');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Failed to get authentication token: Syntax error');
        $auth->getAuthenticationToken();
    }

    public function testCheckUsabilitySuccess(): void
    {
        $mock = new MockHandler([
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                ''
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['handler' => $stack]);

        $factory = $this->createMock(GuzzleClientFactory::class);
        $factory->method('getClient')->willReturn($client);
        $auth = new ManagedCredentialsAuthenticator($factory, 'https://vault.azure.net');
        $auth->checkUsability();
        self::assertCount(1, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals(
            'https://example.com/metadata?api-version=2019-11-01&format=text',
            $request->getUri()->__toString()
        );
        self::assertEquals('GET', $request->getMethod());
        self::assertEquals('Azure PHP Client', $request->getHeader('User-Agent')[0]);
        self::assertEquals('true', $request->getHeader('Metadata')[0]);
        self::assertEquals('application/json', $request->getHeader('Content-type')[0]);
    }

    public function testCheckUsabilityFailure(): void
    {
        $mock = new MockHandler([
            new Response(
                500,
                ['Content-Type' => 'application/json'],
                ''
            ),
            new Response(
                500,
                ['Content-Type' => 'application/json'],
                ''
            ),
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient('https://example.com', ['handler' => $stack, 'backoffMaxTries' => 1]);

        $factory = $this->createMock(GuzzleClientFactory::class);
        $factory->method('getClient')->willReturn($client);
        $auth = new ManagedCredentialsAuthenticator($factory, 'https://vault.azure.net');
        self::expectExceptionMessage(
            // phpcs:ignore Generic.Files.LineLength
            'Instance metadata service not available: Server error: `GET https://example.com/metadata?api-version=2019-11-01&format=text` resulted in a `500 Internal Server Error`'
        );
        self::expectException(ClientException::class);
        $auth->checkUsability();
    }
}
