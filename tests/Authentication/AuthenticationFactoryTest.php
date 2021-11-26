<?php

namespace Keboola\AzureKeyVaultClient\Tests\Authentication;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Keboola\AzureKeyVaultClient\Authentication\AuthenticatorFactory;
use Keboola\AzureKeyVaultClient\Authentication\ClientCredentialsEnvironmentAuthenticator;
use Keboola\AzureKeyVaultClient\Authentication\ManagedCredentialsAuthenticator;
use Keboola\AzureKeyVaultClient\Exception\ClientException;
use Keboola\AzureKeyVaultClient\GuzzleClientFactory;
use Keboola\AzureKeyVaultClient\Tests\BaseTest;
use Psr\Log\NullLogger;
use Psr\Log\Test\TestLogger;

class AuthenticationFactoryTest extends BaseTest
{
    public function testValidClientEnvironmentSettings()
    {
        $authenticationFactory = new AuthenticatorFactory();
        $authenticator = $authenticationFactory->getAuthenticator(
            new GuzzleClientFactory(new NullLogger()),
            'https://vault.azure.net'
        );
        self::assertInstanceOf(ClientCredentialsEnvironmentAuthenticator::class, $authenticator);
    }

    public function testInvalidMetadataSettings()
    {
        /* Even if the instance metadata is not available, the managed credentials authenticator is
            returned because it's verification is optimized out */
        $logger = new TestLogger();
        $mock = self::getMockBuilder(Client::class)
            ->setMethods(['get'])
            ->getMock();
        /** @noinspection PhpParamsInspection */
        $mock->method('get')
            ->with('/metadata?api-version=2019-11-01&format=text')
            ->willThrowException(new \GuzzleHttp\Exception\ClientException('boo', new Request('GET', '/foo/')));
        $factoryMock = self::getMockBuilder(GuzzleClientFactory::class)
            ->setMethods(['getClient'])
            ->setConstructorArgs([$logger])
            ->getMock();
        $factoryMock->method('getClient')
            ->willReturn($mock);

        putenv('AZURE_TENANT_ID=');
        $authenticationFactory = new AuthenticatorFactory();
        /** @noinspection PhpParamsInspection */
        $authenticator = $authenticationFactory->getAuthenticator($factoryMock, 'https://vault.azure.net');
        self::assertInstanceOf(ManagedCredentialsAuthenticator::class, $authenticator);
        self::assertTrue($logger->hasDebugThatContains(
            'ClientCredentialsEnvironmentAuthenticator is not usable: ' .
            'Environment variable "AZURE_TENANT_ID" is not set.'
        ));
    }

    public function testValidManagedSettings()
    {
        putenv('AZURE_TENANT_ID=');
        $mock = new MockHandler([new Response(200, [], '')]);
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

        $authenticationFactory = new AuthenticatorFactory();
        $authenticator = $authenticationFactory->getAuthenticator($factory, 'https://vault.azure.net');
        self::assertInstanceOf(ManagedCredentialsAuthenticator::class, $authenticator);
        self::assertCount(0, $requestHistory);
    }
}
