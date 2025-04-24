<?php

declare(strict_types=1);

namespace Keboola\AzureKeyVaultClient\Tests\Authentication;

use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Keboola\AzureKeyVaultClient\Authentication\FederatedTokenAuthenticator;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\Exception\InvalidResponseException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Tests\BaseTest;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Psr\Log\NullLogger;
use ReflectionClass;

/**
 * @runTestsInSeparateProcesses
 */
class FederatedTokenAuthenticatorTest extends BaseTest
{
    private const TEST_FEDERATED_TOKEN = 'test-federated-token';
    private const TEST_FEDERATED_TOKEN_FILE = '/tmp/test-federated-token.txt';

    public function setUp(): void
    {
        parent::setUp();

        // Set up the federated token file
        file_put_contents(self::TEST_FEDERATED_TOKEN_FILE, self::TEST_FEDERATED_TOKEN);

        // Set the environment variable for the federated token file
        putenv('AZURE_FEDERATED_TOKEN_FILE=' . self::TEST_FEDERATED_TOKEN_FILE);
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        // Clean up the test file
        if (file_exists(self::TEST_FEDERATED_TOKEN_FILE)) {
            unlink(self::TEST_FEDERATED_TOKEN_FILE);
        }
    }

    public function testCheckUsabilityFailureMissingTenant(): void
    {
        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
        );
        putenv('AZURE_TENANT_ID=');
        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Environment variable "AZURE_TENANT_ID" is not set.');
        $authenticator->checkUsability();
    }

    public function testCheckUsabilityFailureMissingClient(): void
    {
        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
        );
        putenv('AZURE_CLIENT_ID=');
        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Environment variable "AZURE_CLIENT_ID" is not set.');
        $authenticator->checkUsability();
    }

    public function testCheckUsabilityFailureMissingFederatedTokenFile(): void
    {
        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
        );
        putenv('AZURE_FEDERATED_TOKEN_FILE=');
        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Environment variable "AZURE_FEDERATED_TOKEN_FILE" is not set.');
        $authenticator->checkUsability();
    }

    public function testCheckUsabilityFailureFederatedTokenFileNotFound(): void
    {
        // Set up required environment variables
        putenv('AZURE_TENANT_ID=test-tenant');
        putenv('AZURE_CLIENT_ID=test-client');
        putenv('AZURE_FEDERATED_TOKEN_FILE=/non-existent-file');

        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
        );

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Federated token file "/non-existent-file" does not exist.');
        $authenticator->checkUsability();
    }

    public function testValidEnvironmentSettings(): void
    {

        $logsHandler = new TestHandler();
        $logger = new Logger('test', [$logsHandler]);

        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory($logger),
            'https://vault.azure.net',
        );
        $authenticator->checkUsability();
        self::assertTrue($logsHandler->hasDebugThatContains(
            'AZURE_AUTHORITY_HOST environment variable is not specified, falling back to default.',
        ));
    }

    public function testValidFullEnvironmentSettings(): void
    {
        putenv('AZURE_AUTHORITY_HOST=https://login.example.com');

        $logsHandler = new TestHandler();
        $logger = new Logger('test', [$logsHandler]);

        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory($logger),
            'https://vault.azure.net',
        );
        $authenticator->checkUsability();
        self::assertFalse($logsHandler->hasDebugThatContains(
            'AZURE_AUTHORITY_HOST environment variable is not specified, falling back to default.',
        ));
    }

    public function testAuthenticate(): void
    {
        // Set up required environment variables
        putenv('AZURE_TENANT_ID=test-tenant');
        putenv('AZURE_CLIENT_ID=test-client');
        putenv('AZURE_FEDERATED_TOKEN_FILE=' . self::TEST_FEDERATED_TOKEN_FILE);

        // Create a mock handler for the token request
        $mockHandler = new MockHandler([
            new Response(200, [], (string) json_encode([
                'access_token' => 'test-access-token',
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ])),
        ]);

        $handlerStack = HandlerStack::create($mockHandler);
        $container = [];
        $history = Middleware::history($container);
        $handlerStack->push($history);

        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
            ['handler' => $handlerStack],
        );

        $token = $authenticator->getAuthenticationToken();
        self::assertSame('test-access-token', $token);

        // Verify the request
        self::assertCount(1, $container);
        $request = $container[0]['request'];
        self::assertInstanceOf(Request::class, $request);
        self::assertSame('POST', $request->getMethod());
        self::assertSame(
            'https://login.microsoftonline.com/test-tenant/oauth2/v2.0/token',
            (string) $request->getUri(),
        );
        self::assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));

        // Verify the request body is properly URL-encoded with exact values
        $requestBody = (string) $request->getBody();
        parse_str($requestBody, $parsedBody);
        self::assertSame([
            'grant_type' => 'client_credentials',
            'client_id' => 'test-client',
            'client_assertion' => self::TEST_FEDERATED_TOKEN,
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'scope' => 'https://vault.azure.net/.default',
        ], $parsedBody);
    }

    public function testAuthenticateWithCustomAuthorityHost(): void
    {
        putenv('AZURE_AUTHORITY_HOST=https://login.example.com');
        putenv('AZURE_TENANT_ID=test-tenant');
        putenv('AZURE_CLIENT_ID=test-client');
        putenv('AZURE_FEDERATED_TOKEN_FILE=' . self::TEST_FEDERATED_TOKEN_FILE);

        // Create a mock handler for the token request
        $mockHandler = new MockHandler([
            new Response(
                200,
                [
                    'Content-Type' => 'application/json',
                ],
                (string) json_encode([
                    'token_type' => 'Bearer',
                    'expires_in' => 3600,
                    'ext_expires_in' => 3600,
                    'expires_on' => '1589810452',
                    'not_before' => '1589806552',
                    'resource' => 'https://vault.azure.net',
                    'access_token' => 'ey....ey',
                ]),
            ),
        ]);

        $handlerStack = HandlerStack::create($mockHandler);
        $container = [];
        $history = Middleware::history($container);
        $handlerStack->push($history);

        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
            ['handler' => $handlerStack],
        );

        $token = $authenticator->getAuthenticationToken();
        self::assertSame('ey....ey', $token);

        // Verify the request
        self::assertCount(1, $container);
        $request = $container[0]['request'];
        self::assertInstanceOf(Request::class, $request);
        self::assertSame('POST', $request->getMethod());
        self::assertSame('https://login.example.com/test-tenant/oauth2/v2.0/token', (string) $request->getUri());
        self::assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));

        // Verify the request body is properly URL-encoded with exact values
        $requestBody = (string) $request->getBody();
        parse_str($requestBody, $parsedBody);
        self::assertSame([
            'grant_type' => 'client_credentials',
            'client_id' => 'test-client',
            'client_assertion' => self::TEST_FEDERATED_TOKEN,
            'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'scope' => 'https://vault.azure.net/.default',
        ], $parsedBody);
    }

    public function testAuthenticateTokenError(): void
    {
        // Set up required environment variables
        putenv('AZURE_TENANT_ID=test-tenant');
        putenv('AZURE_CLIENT_ID=test-client');
        putenv('AZURE_FEDERATED_TOKEN_FILE=' . self::TEST_FEDERATED_TOKEN_FILE);

        // Create a mock handler that throws an exception
        $mockHandler = new MockHandler([
            new RequestException(
                'Token request failed',
                new Request('POST', 'https://example.com'),
                new Response(400),
            ),
        ]);

        $handlerStack = HandlerStack::create($mockHandler);

        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
            ['handler' => $handlerStack],
        );

        $this->expectException(ClientException::class);
        $this->expectExceptionMessage('Failed to get authentication token: Token request failed');
        $authenticator->getAuthenticationToken();
    }

    public function testAuthenticateTokenMalformed(): void
    {
        // Set up required environment variables
        putenv('AZURE_TENANT_ID=test-tenant');
        putenv('AZURE_CLIENT_ID=test-client');
        putenv('AZURE_FEDERATED_TOKEN_FILE=' . self::TEST_FEDERATED_TOKEN_FILE);

        // Create a mock handler with malformed response
        $mockHandler = new MockHandler([
            new Response(200, [], (string) json_encode([
                'token_type' => 'Bearer',
                'expires_in' => 3600,
                // Missing access_token
            ])),
        ]);

        $handlerStack = HandlerStack::create($mockHandler);

        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
            ['handler' => $handlerStack],
        );

        $this->expectException(InvalidResponseException::class);
        $this->expectExceptionMessage(
            'Access token not provided in response: {"token_type":"Bearer","expires_in":3600}',
        );
        $authenticator->getAuthenticationToken();
    }

    public function testTokenExpiration(): void
    {
        // Set up required environment variables
        putenv('AZURE_TENANT_ID=test-tenant');
        putenv('AZURE_CLIENT_ID=test-client');
        putenv('AZURE_FEDERATED_TOKEN_FILE=' . self::TEST_FEDERATED_TOKEN_FILE);

        // Create a mock handler for the token request
        $mockHandler = new MockHandler([
            new Response(200, [], (string) json_encode([
                'access_token' => 'test-access-token-1',
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ])),
            new Response(200, [], (string) json_encode([
                'access_token' => 'test-access-token-2',
                'expires_in' => 3600,
                'token_type' => 'Bearer',
            ])),
        ]);

        $handlerStack = HandlerStack::create($mockHandler);
        $container = [];
        $history = Middleware::history($container);
        $handlerStack->push($history);

        $authenticator = new FederatedTokenAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net',
            ['handler' => $handlerStack],
        );

        // First call should get the token
        $token1 = $authenticator->getAuthenticationToken();
        self::assertSame('test-access-token-1', $token1);

        // Second call should use the cached token
        $token2 = $authenticator->getAuthenticationToken();
        self::assertSame('test-access-token-1', $token2);

        // Verify only one request was made
        self::assertCount(1, $container);

        // Now let's simulate token expiration by modifying the tokenExpiresAt property
        $reflection = new ReflectionClass($authenticator);
        $property = $reflection->getProperty('tokenExpiresAt');
        $property->setAccessible(true);
        $property->setValue($authenticator, time() - 1); // Set expiration to the past

        // Third call should get a new token
        $token3 = $authenticator->getAuthenticationToken();
        self::assertSame('test-access-token-2', $token3);

        // Verify two requests were made
        self::assertCount(2, $container);
    }
}
