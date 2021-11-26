<?php

namespace Keboola\AzureKeyVaultClient\Tests\Authentication;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Keboola\AzureKeyVaultClient\Authentication\ClientCredentialsEnvironmentAuthenticator;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Tests\BaseTest;
use Psr\Log\NullLogger;
use Psr\Log\Test\TestLogger;

class ClientCredentialsEnvironmentAuthenticatorTest extends BaseTest
{
    public function testCheckUsabilityFailureMissingTenant()
    {
        $authenticator = new ClientCredentialsEnvironmentAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net'
        );
        putenv('AZURE_TENANT_ID=');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Environment variable "AZURE_TENANT_ID" is not set.');
        $authenticator->checkUsability();
    }

    public function testCheckUsabilityFailureMissingClient()
    {
        $authenticator = new ClientCredentialsEnvironmentAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net'
        );
        putenv('AZURE_CLIENT_ID=');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Environment variable "AZURE_CLIENT_ID" is not set.');
        $authenticator->checkUsability();
    }

    public function testCheckUsabilityFailureMissingSecret()
    {
        $authenticator = new ClientCredentialsEnvironmentAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net'
        );
        putenv('AZURE_CLIENT_SECRET=');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Environment variable "AZURE_CLIENT_SECRET" is not set.');
        $authenticator->checkUsability();
    }

    public function testValidEnvironmentSettings()
    {
        $logger = new TestLogger();
        $authenticator = new ClientCredentialsEnvironmentAuthenticator(
            new GuzzleClientFactory($logger),
            'https://vault.azure.net'
        );
        $authenticator->checkUsability();
        self::assertTrue($logger->hasDebugThatContains(
            'AZURE_AD_RESOURCE environment variable is not specified, falling back to default.'
        ));
        self::assertTrue($logger->hasDebugThatContains(
            'AZURE_ENVIRONMENT environment variable is not specified, falling back to default.'
        ));
    }

    public function testValidFullEnvironmentSettings()
    {
        putenv('AZURE_AD_RESOURCE=https://example.com');
        putenv('AZURE_ENVIRONMENT=123');
        $logger = new TestLogger();
        $authenticator = new ClientCredentialsEnvironmentAuthenticator(
            new GuzzleClientFactory($logger),
        'https://vault.azure.net'
        );
        $authenticator->checkUsability();
        self::assertFalse($logger->hasDebugThatContains(
            'AZURE_AD_RESOURCE environment variable is not specified, falling back to default.'
        ));
        self::assertFalse($logger->hasDebugThatContains(
            'AZURE_ENVIRONMENT environment variable is not specified, falling back to default.'
        ));
    }

    public function testInvalidAdResource()
    {
        $logger = new TestLogger();
        putenv('AZURE_AD_RESOURCE=not-an-url');
        putenv('AzureCloud=123');
        self::expectException(ClientException::class);
        self::expectExceptionMessage(
            'Invalid options when creating client: Value "not-an-url" is invalid: This value is not a valid URL.'
        );
        new ClientCredentialsEnvironmentAuthenticator(new GuzzleClientFactory($logger), 'https://vault.azure.net');
    }

    public function testAuthenticate()
    {
        $mock = new MockHandler($this->getMockAuthResponses());
        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient( 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->setConstructorArgs([new NullLogger()])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator($factory, 'https://vault.azure.net');
        $token = $auth->getAuthenticationToken();
        self::assertCount(2, $requestHistory);
        // call second time, value is cached and no new request are made
        $token2 = $auth->getAuthenticationToken();
        self::assertCount(2, $requestHistory);
        self::assertSame($token, $token2);
        self::assertEquals('ey....ey', $token);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://management.azure.com/metadata/endpoints?api-version=2020-01-01', $request->getUri()->__toString());
        self::assertEquals('GET', $request->getMethod());
        self::assertEquals('Azure PHP Client', $request->getHeader('User-Agent')[0]);
        self::assertEquals('application/json', $request->getHeader('Content-type')[0]);
        /** @var Request $request */
        $request = $requestHistory[1]['request'];
        self::assertEquals('https://login.windows.net/tenant123/oauth2/token', $request->getUri()->__toString());
        self::assertEquals('POST', $request->getMethod());
        self::assertEquals('Azure PHP Client', $request->getHeader('User-Agent')[0]);
        self::assertEquals('application/x-www-form-urlencoded', $request->getHeader('Content-type')[0]);
        self::assertEquals(
            'grant_type=client_credentials&client_id=client123&client_secret=secret123&resource=https%3A%2F%2Fvault.azure.net',
            $request->getBody()->getContents()
        );
    }

    public function testAuthenticateCustomMetadata()
    {
        $metadata = $this->getSampleArmMetadata();
        $metadata[0]['authentication']['loginEndpoint'] = 'https://my-custom-login/';
        $metadata[0]['name'] = 'my-azure';
        putenv('AZURE_ENVIRONMENT=my-azure');
        putenv('AZURE_AD_RESOURCE=https://example.com');

        $mock = new MockHandler([
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode($metadata)
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
        $auth = new ClientCredentialsEnvironmentAuthenticator($factory, 'https://vault.azure.net');
        $token = $auth->getAuthenticationToken();
        self::assertEquals('ey....ey', $token);
        self::assertCount(2, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        self::assertEquals('GET', $request->getMethod());
        self::assertEquals('Azure PHP Client', $request->getHeader('User-Agent')[0]);
        self::assertEquals('application/json', $request->getHeader('Content-type')[0]);
        $request = $requestHistory[1]['request'];
        self::assertEquals('https://my-custom-login/tenant123/oauth2/token', $request->getUri()->__toString());
        self::assertEquals('POST', $request->getMethod());
        self::assertEquals('Azure PHP Client', $request->getHeader('User-Agent')[0]);
        self::assertEquals('application/x-www-form-urlencoded', $request->getHeader('Content-type')[0]);
        self::assertEquals(
            'grant_type=client_credentials&client_id=client123&client_secret=secret123&resource=https%3A%2F%2Fvault.azure.net',
            $request->getBody()->getContents()
        );
    }

    public function testAuthenticateInvalidMetadata()
    {
        putenv('AZURE_ENVIRONMENT=non-existent');
        $mock = new MockHandler([
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                json_encode($this->getSampleArmMetadata())
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
        $auth = new ClientCredentialsEnvironmentAuthenticator($factory, 'https://vault.azure.net');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Cloud "non-existent" not found in instance metadata');
        $auth->getAuthenticationToken();
    }

    public function testAuthenticateMetadataRetry()
    {
        $mock = new MockHandler([
            new Response(
                500,
                ['Content-Type' => 'application/json'],
                'boo'
            ),
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
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $factory = new GuzzleClientFactory(new NullLogger());
        $client = $factory->getClient( 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->setConstructorArgs([new NullLogger()])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator($factory, 'https://vault.azure.net');
        $token = $auth->getAuthenticationToken();
        self::assertEquals('ey....ey', $token);
    }

    public function testAuthenticateMetadataFailure()
    {
        $mock = new MockHandler([
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                'boo'
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
        $auth = new ClientCredentialsEnvironmentAuthenticator($factory, 'https://vault.azure.net');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Failed to get instance metadata: json_decode error: Syntax error');
        $auth->getAuthenticationToken();
    }

    public function testAuthenticateMalformedMetadata()
    {
        $mock = new MockHandler([
            new Response(
                200,
                ['Content-Type' => 'application/json'],
                '"boo"'
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
        $auth = new ClientCredentialsEnvironmentAuthenticator($factory, 'https://vault.azure.net');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Invalid metadata contents: "boo"');
        $auth->getAuthenticationToken();
    }

    public function testAuthenticateTokenError()
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
                '{"boo"}'
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
        $auth = new ClientCredentialsEnvironmentAuthenticator($factory, 'https://vault.azure.net');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Failed to get authentication token: json_decode error: Syntax error');
        $auth->getAuthenticationToken();
    }

    public function testAuthenticateTokenMalformed()
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
                '{"error": "boo"}'
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
        $auth = new ClientCredentialsEnvironmentAuthenticator($factory, 'https://vault.azure.net');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Access token not provided in response: {"error":"boo"}');
        $auth->getAuthenticationToken();
    }
}
