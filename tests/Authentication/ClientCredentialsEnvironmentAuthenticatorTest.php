<?php

namespace Keboola\AzureKeyVaultClient\Tests\Authentication;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Keboola\AzureKeyVaultClient\Authentication\ClientCredentialsEnvironmentAuthenticator;
use Keboola\AzureKeyVaultClient\Client;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Psr\Log\Test\TestLogger;

class ClientCredentialsEnvironmentAuthenticatorTest extends TestCase
{
    public function setUp()
    {
        parent::setUp();
        putenv('AZURE_TENANT_ID=tenant123');
        putenv('AZURE_CLIENT_ID=client123');
        putenv('AZURE_CLIENT_SECRET=secret123');
        putenv('AZURE_AD_RESOURCE=');
        putenv('AZURE_ENVIRONMENT=');
    }

    public function testInvalidEnvironmentSettings()
    {
        putenv('AZURE_TENANT_ID=');
        putenv('AZURE_CLIENT_ID=');
        putenv('AZURE_CLIENT_SECRET=');
        self::expectException(ClientException::class);
        self::expectExceptionMessage(
            'Environment variable "AZURE_TENANT_ID" is not set. Environment variable "AZURE_CLIENT_ID" is not set. ' .
            'Environment variable "AZURE_CLIENT_SECRET" is not set.'
        );
        new ClientCredentialsEnvironmentAuthenticator(new NullLogger(), new GuzzleClientFactory());
    }

    public function testValidEnvironmentSettings()
    {
        $logger = new TestLogger();
        new ClientCredentialsEnvironmentAuthenticator($logger, new GuzzleClientFactory());
        self::assertTrue($logger->hasDebugThatContains(
            'AZURE_AD_RESOURCE environment variable is not specified, falling back to default.'
        ));
        self::assertTrue($logger->hasDebugThatContains(
            'AZURE_ENVIRONMENT environment variable is not specified, falling back to default.'
        ));
    }

    public function testFullEnvironmentSettings()
    {
        putenv('AZURE_AD_RESOURCE=https://example.com');
        putenv('AZURE_ENVIRONMENT=123');
        $logger = new TestLogger();
        new ClientCredentialsEnvironmentAuthenticator($logger, new GuzzleClientFactory());
        self::assertFalse($logger->hasDebugThatContains(
            'AZURE_AD_RESOURCE environment variable is not specified, falling back to default.'
        ));
        self::assertFalse($logger->hasDebugThatContains(
            'AZURE_ENVIRONMENT environment variable is not specified, falling back to default.'
        ));
    }

    public function testInvalidAdResource()
    {
        putenv('AZURE_AD_RESOURCE=not-an-url');
        putenv('AzureCloud=123');
        $logger = new TestLogger();
        self::expectException(ClientException::class);
        self::expectExceptionMessage(
            'Invalid parameters when creating client: Value "not-an-url" is invalid: This value is not a valid URL.'
        );
        new ClientCredentialsEnvironmentAuthenticator($logger, new GuzzleClientFactory());
    }

    public function testAuthenticate()
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
        ]);

        $requestHistory = [];
        $history = Middleware::history($requestHistory);
        $stack = HandlerStack::create($mock);
        $stack->push($history);
        $factory = new GuzzleClientFactory();
        $client = $factory->getClient(new NullLogger(), 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator(new NullLogger(), $factory);
        $token = $auth->getAuthenticationToken();
        self::assertEquals('ey....ey', $token);
        self::assertCount(2, $requestHistory);
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
        self::assertEquals('application/json', $request->getHeader('Content-type')[0]);
        self::assertEquals('client_credentials', $request->getHeader('form_params')['grant_type']);
        self::assertEquals('client123', $request->getHeader('form_params')['client_id']);
        self::assertEquals('secret123', $request->getHeader('form_params')['client_secret']);
        self::assertEquals('https://vault.azure.net', $request->getHeader('form_params')['resource']);
    }

    public function testAuthenticateCustomMetadata()
    {
        $metadata = $this->getSampleArmMetadata();
        $metadata[0]['authentication']['loginEndpoint'] = 'https://my-custom-login/';
        $metadata[0]['suffixes']['keyVaultDns'] = 'https://my-custom/key-vault';
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
        $factory = new GuzzleClientFactory();
        $client = $factory->getClient(new NullLogger(), 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator(new NullLogger(), $factory);
        $token = $auth->getAuthenticationToken();
        self::assertEquals('ey....ey', $token);
        self::assertCount(2, $requestHistory);
        /** @var Request $request */
        $request = $requestHistory[0]['request'];
        self::assertEquals('https://example.com', $request->getUri()->__toString());
        self::assertEquals('GET', $request->getMethod());
        self::assertEquals('Azure PHP Client', $request->getHeader('User-Agent')[0]);
        self::assertEquals('application/json', $request->getHeader('Content-type')[0]);
        /** @var Request $request */
        $request = $requestHistory[1]['request'];
        self::assertEquals('https://my-custom-login/tenant123/oauth2/token', $request->getUri()->__toString());
        self::assertEquals('POST', $request->getMethod());
        self::assertEquals('Azure PHP Client', $request->getHeader('User-Agent')[0]);
        self::assertEquals('application/json', $request->getHeader('Content-type')[0]);
        self::assertEquals('client_credentials', $request->getHeader('form_params')['grant_type']);
        self::assertEquals('client123', $request->getHeader('form_params')['client_id']);
        self::assertEquals('secret123', $request->getHeader('form_params')['client_secret']);
        self::assertEquals('https://https://my-custom/key-vault', $request->getHeader('form_params')['resource']);
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
        $factory = new GuzzleClientFactory();
        $client = $factory->getClient(new NullLogger(), 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator(new NullLogger(), $factory);
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
        $factory = new GuzzleClientFactory();
        $client = $factory->getClient(new NullLogger(), 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator(new NullLogger(), $factory);
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
        $factory = new GuzzleClientFactory();
        $client = $factory->getClient(new NullLogger(), 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator(new NullLogger(), $factory);
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
        $factory = new GuzzleClientFactory();
        $client = $factory->getClient(new NullLogger(), 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator(new NullLogger(), $factory);
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
        $factory = new GuzzleClientFactory();
        $client = $factory->getClient(new NullLogger(), 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator(new NullLogger(), $factory);
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
        $factory = new GuzzleClientFactory();
        $client = $factory->getClient(new NullLogger(), 'https://example.com', ['handler' => $stack]);

        $factory = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->getMock();
        $factory->method('getClient')
            ->willReturn($client);
        /** @var GuzzleClientFactory $factory */
        $auth = new ClientCredentialsEnvironmentAuthenticator(new NullLogger(), $factory);
        self::expectException(ClientException::class);
        self::expectExceptionMessage('Access token not provided in response: {"error":"boo"}');
        $auth->getAuthenticationToken();
    }

    private function getSampleArmMetadata()
    {
        return [
            [
                'portal' => 'https://portal.azure.com',
                'authentication' => [
                    'loginEndpoint' => 'https://login.windows.net/',
                    'audiences' => [
                        'https://management.core.windows.net/',
                        'https://management.azure.com/'
                    ],
                    'tenant' => 'common',
                    'identityProvider' => 'AAD',
                ],
                'media' => 'https://rest.media.azure.net',
                'graphAudience' => 'https://graph.windows.net/',
                'graph' => 'https://graph.windows.net/',
                'name' => 'AzureCloud',
                'suffixes' => [
                    'azureDataLakeStoreFileSystem' => 'azuredatalakestore.net',
                    'acrLoginServer' => 'azurecr.io',
                    'sqlServerHostname' => 'database.windows.net',
                    'azureDataLakeAnalyticsCatalogAndJob' => 'azuredatalakeanalytics.net',
                    'keyVaultDns' => 'vault.azure.net',
                    'storage' => 'core.windows.net',
                    'azureFrontDoorEndpointSuffix' => 'azurefd.net',
                ],
                'batch' => 'https://batch.core.windows.net/',
                'resourceManager' => 'https://management.azure.com/',
                'vmImageAliasDoc' => 'https://raw.githubusercontent.com/Azure/azure-rest-api-specs/master/arm-compute/quickstart-templates/aliases.json',
                'activeDirectoryDataLake' => 'https://datalake.azure.net/',
                'sqlManagement' => 'https://management.core.windows.net:8443/',
                'gallery' => 'https://gallery.azure.com/',
            ],
        ];
    }
}
