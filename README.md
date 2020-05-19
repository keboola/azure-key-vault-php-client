# Azure Key Vault PHP Client [![Build Status](https://dev.azure.com/keboola-dev/azure-key-vault-php-client/_apis/build/status/keboola.azure-key-vault-php-client?branchName=master)](https://dev.azure.com/keboola-dev/azure-key-vault-php-client/_build/latest?definitionId=12&branchName=master) [![Maintainability](https://api.codeclimate.com/v1/badges/fe983803eb7d71a87a34/maintainability)](https://codeclimate.com/github/keboola/azure-key-vault-php-client/maintainability) [![Test Coverage](https://api.codeclimate.com/v1/badges/fe983803eb7d71a87a34/test_coverage)](https://codeclimate.com/github/keboola/azure-key-vault-php-client/test_coverage)

PHP client for [Azure Key Vault](https://docs.microsoft.com/en-us/rest/api/keyvault/).

Supports the following [authentication methods](https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authorization):

- Client credentials supplied in `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` environment variables
- Managed identity (supplied in `MSI_ENDPOINT` and `MSI_SECRET` environment variables).

Only key encrypt and decrypt methods are currently implemented.

## Installation

    composer require keboola/azure-key-vault-php-client
    
## Usage

Create client instance and encrypt data:

```php 
$client = new Client(
    $logger,
    new GuzzleClientFactory(),
    new AuthenticatorFactory(),
    https://my-test-vault.vault.azure.net
);

$result = $client->encrypt(
    new EncryptDecryptRequest('RSA1_5', 'test'),
    'my-test-key',
    'abcabcabcabcabcabcabcabcabcabcab'
);
```

## Development

Run tests with:

    docker-compose run --rm testsXX

where XX is PHP version (56 - 74), e.g.:

    docker-compose run --rm tests70
