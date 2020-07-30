<?php

namespace Keboola\AzureKeyVaultClient\Tests\Authentication;

use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
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
        $authenticator = $authenticationFactory->getAuthenticator(new GuzzleClientFactory(new NullLogger()));
        self::assertInstanceOf(ClientCredentialsEnvironmentAuthenticator::class, $authenticator);
    }

    public function testInvalidClientEnvironmentSettingsMissingTenant()
    {
        $logger = new TestLogger();
        putenv('AZURE_TENANT_ID=');
        passthru('env');
        try {
            $authenticationFactory = new AuthenticatorFactory();
            $authenticationFactory->getAuthenticator(new GuzzleClientFactory($logger));
            self::fail('Must throw exception');
        } catch (ClientException $e) {
            self::assertContains('No suitable authentication method found.', $e->getMessage());
        }
        var_dump($e);
        self::assertTrue($logger->hasDebugThatContains('Keboola\AzureKeyVaultClient\Authentication\ClientCredentialsEnvironmentAuthenticator is not usable.'));
        self::assertTrue($logger->hasDebugThatContains('Keboola\AzureKeyVaultClient\Authentication\ManagedCredentialsAuthenticator is not usable.'));
    }

    public function testInvalidClientEnvironmentSettingsMissingClient()
    {
        putenv('AZURE_CLIENT_ID=');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('No suitable authentication method found.');
        $authenticationFactory = new AuthenticatorFactory();
        $authenticationFactory->getAuthenticator(new GuzzleClientFactory(new NullLogger()));
    }

    public function testInvalidClientEnvironmentSettingsMissingSecret()
    {
        putenv('AZURE_CLIENT_SECRET=');
        self::expectException(ClientException::class);
        self::expectExceptionMessage('No suitable authentication method found.');
        $authenticationFactory = new AuthenticatorFactory();
        $authenticationFactory->getAuthenticator(new GuzzleClientFactory(new NullLogger()));
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
        $authenticator = $authenticationFactory->getAuthenticator($factory);
        self::assertInstanceOf(ManagedCredentialsAuthenticator::class, $authenticator);
        self::assertCount(1, $requestHistory);
    }
}
