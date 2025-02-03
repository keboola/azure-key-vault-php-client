# Azure Key Vault PHP Client [![Build Status](https://dev.azure.com/keboola-dev/azure-key-vault-php-client/_apis/build/status/keboola.azure-key-vault-php-client?branchName=master)](https://dev.azure.com/keboola-dev/azure-key-vault-php-client/_build/latest?definitionId=12&branchName=master) [![Maintainability](https://api.codeclimate.com/v1/badges/fe983803eb7d71a87a34/maintainability)](https://codeclimate.com/github/keboola/azure-key-vault-php-client/maintainability) [![Test Coverage](https://api.codeclimate.com/v1/badges/fe983803eb7d71a87a34/test_coverage)](https://codeclimate.com/github/keboola/azure-key-vault-php-client/test_coverage)

PHP client for [Azure Key Vault](https://docs.microsoft.com/en-us/rest/api/keyvault/).

Supports the following [authentication methods](https://docs.microsoft.com/en-us/azure/developer/go/azure-sdk-authorization):

- **Client credentials** supplied in `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` environment variables
- **Managed identity** picked automatically if client credentials not specified and [Azure Instance Metadata](https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service) is available.

Only key encrypt and decrypt methods are currently implemented.

## Installation

    composer require keboola/azure-key-vault-client
    
## Usage

Create client instance and encrypt data:

```php 
$client = new Client(
    new GuzzleClientFactory($logger),
    new AuthenticatorFactory(),
    'https://my-test-vault.vault.azure.net'
);

$result = $client->encrypt(
    new EncryptRequest(EncryptRequest::RSA_OAEP_256, 'test'),
    'my-test-key',
    'abcabcabcabcabcabcabcabcabcabcab'
);
```

## Development

Run tests with:

    docker compose run --rm testsXX

where XX is PHP version (56 - 74), e.g.:

    docker compose run --rm tests70

### Resources Setup

Create a resource group:

	az group create --name testing-azure-key-vault-php-client --location "East US"

Create a service principal:

	az ad sp create-for-rbac --name testing-azure-key-vault-php-client

Use the response to set values `TEST_CLIENT_ID`, `TEST_CLIENT_SECRET` and `TEST_TENANT_ID` in the `.env.` file:

```json	
{
  "appId": "268a6f05-xxxxxxxxxxxxxxxxxxxxxxxxxxx", //-> TEST_CLIENT_ID
  "displayName": "testing-azure-key-vault-php-client",
  "name": "http://testing-azure-key-vault-php-client",
  "password": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", //-> TEST_CLIENT_SECRET
  "tenant": "9b85ee6f-xxxxxxxxxxxxxxxxxxxxxxxxxxx" //-> TEST_TENANT_ID
}
```

Get ID of the service principal:

	az ad sp list --filter "displayname eq 'testing-azure-key-vault-php-client'" --query [].objectId

Get ID of a group to which the current user belongs (e.g. "Developers"):

	az ad group list --filter "displayname eq 'Developers'" --query [].objectId

Deploy the key vault, provide tentant ID, service principal ID and group ID from the previous commands:

	az deployment group create --resource-group testing-azure-key-vault-php-client --template-file arm-template.json --parameters vault_name=testing-key-vault-client tenant_id=9b85ee6f-xxxxxxxxxxxxxxxxxxxxxxxxxxx service_principal_object_id=7f7a8a4c-xxxxxxxxxxxxxxxxxxxxxxxxxxx group_object_id=a1e8da73-xxxxxxxxxxxxxxxxxxxxxxxxxxx

Create key:

	az keyvault key create --name test-key --vault-name testing-key-vault-client --query key.kid

returns e.g. `https://testing-key-vault-client.vault.azure.net/keys/test-key/b7c28xxxxxxxxxxxxxxxxxxxxxxxxxxx`, use this to set values in `.env` file:
- `TEST_KEY_VAULT_URL` - https://testing-key-vault-client.vault.azure.net
- `TEST_KEY_NAME` - test-key
- `TEST_KEY_VERSION` - b7c28xxxxxxxxxxxxxxxxxxxxxxxxxxx

## License

MIT licensed, see [LICENSE](./LICENSE) file.
